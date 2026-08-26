"""Import a Ghidra headless export into the evidence graph.

Kept separate from the runner on purpose. Running Ghidra needs a JVM, a
multi-gigabyte install, and minutes of wall time; importing its output needs
none of those. Splitting them means the translation layer - where the bugs
actually live - is unit-testable against recorded exports on any machine, and
that a colleague can hand over an export directory without handing over their
whole environment.

The importer converges onto artifact ids that triage already minted for the
same file, because both derive identity from the same addresses and text. A
Ghidra run over an already-triaged binary therefore *enriches* the graph rather
than duplicating it, and any claim both engines agree on ends up with two
attestations instead of two near-identical rows.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterator

from aether.adapters.triage import detectors
from aether.errors import AdapterError
from aether.evidence.models import EvidenceRef
from aether.project.store import Project, RunContext
from aether.util import sanitize_text

#: Streams the export may contain. A missing stream is not an error - an older
#: script, or a program with no strings, simply omits it.
STREAMS = (
    "sections",
    "functions",
    "strings",
    "symbols",
    "imports",
    "exports",
    "xrefs",
    "decompilation",
)

#: Ghidra names undiscovered functions FUN_00401000 and friends. Those are
#: artifacts (a function really is there) but not claims: "this binary defines
#: a function called FUN_00401000" asserts nothing a reviewer can act on.
_AUTO_NAME_PREFIXES = ("FUN_", "SUB_", "thunk_FUN_", "LAB_", "UNK_")

#: Cap on xref artifacts per import. A call to malloc in a large binary has
#: thousands; a handful is enough to evidence the claim.
MAX_XREF_EVIDENCE = 25

MAX_STRING_LENGTH = 512
MAX_DECOMPILATION_CHARS = 60000


def read_export(export_dir: str) -> dict[str, Any]:
    """Load an export directory into memory, validating its shape."""
    meta_path = os.path.join(export_dir, "meta.json")
    if not os.path.isfile(meta_path):
        raise AdapterError(
            f"{export_dir} does not look like an Aether/Ghidra export "
            "(no meta.json). Was AetherExport.py given the right output path?"
        )
    with open(meta_path, "r", encoding="utf-8") as handle:
        meta = json.load(handle)

    export: dict[str, Any] = {"meta": meta}
    for stream in STREAMS:
        export[stream] = list(_read_jsonl(os.path.join(export_dir, f"{stream}.jsonl")))
    return export


def _read_jsonl(path: str) -> Iterator[dict[str, Any]]:
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AdapterError(
                    f"{os.path.basename(path)}:{line_number} is not valid JSON: {exc}"
                ) from exc
            if isinstance(record, dict):
                yield record


def import_export(
    rc: RunContext,
    project: Project,
    export: dict[str, Any],
    object_id: str,
    *,
    producer: str = "aether-ghidra",
    max_xrefs: int = 20000,
) -> dict[str, Any]:
    """Write an in-memory export into the graph under ``object_id``."""
    counts: dict[str, int] = {}

    counts["sections"] = _import_sections(rc, object_id, export)
    functions = _import_functions(rc, object_id, export, producer)
    counts["functions"] = functions["artifacts"]
    counts["function_claims"] = functions["claims"]

    counts["strings"] = _import_strings(rc, object_id, export, producer)
    counts["symbols"] = _import_symbols(rc, object_id, export)
    xref_index = _import_xrefs(rc, object_id, export, max_xrefs)
    counts["xrefs"] = xref_index["count"]
    decompilation = _import_decompilation(rc, object_id, export)
    counts["decompilation"] = len(decompilation)

    symbols = _import_imports_exports(
        rc, object_id, export, producer, xref_index["by_target_name"], decompilation
    )
    counts.update(symbols)
    return counts


def _import_sections(rc: RunContext, object_id: str, export: dict[str, Any]) -> int:
    count = 0
    for record in export.get("sections", []):
        if record.get("addr_start") is None:
            continue
        rc.artifact(
            "section",
            {
                "name": str(record.get("name") or "unnamed"),
                "addr_start": int(record["addr_start"]),
                "addr_end": _optional_int(record.get("addr_end")),
                "permissions": str(record.get("permissions") or "r"),
                "initialized": bool(record.get("initialized", True)),
            },
            object_id=object_id,
        )
        count += 1
    return count


def _import_functions(
    rc: RunContext, object_id: str, export: dict[str, Any], producer: str
) -> dict[str, int]:
    artifacts = claims = 0
    for record in export.get("functions", []):
        if record.get("addr_start") is None or not record.get("name"):
            continue
        name = str(record["name"])
        data: dict[str, Any] = {
            "name": name,
            "addr_start": int(record["addr_start"]),
            "addr_end": _optional_int(record.get("addr_end")),
            "size": _optional_int(record.get("size")),
            "signature": _optional_text(record.get("signature")),
            "calling_convention": _optional_text(record.get("calling_convention")),
            "is_thunk": bool(record.get("is_thunk", False)),
            "is_external": bool(record.get("is_external", False)),
            "param_count": _optional_int(record.get("param_count")),
        }
        artifact = rc.artifact("function", _drop_none(data), object_id=object_id)
        artifacts += 1

        if _is_auto_named(name) or data["is_thunk"] or data["is_external"]:
            continue
        rc.add_claim(
            "defines_function",
            {"name": name, "addr": int(record["addr_start"])},
            [EvidenceRef(artifact.artifact_id, "locus")],
            subject_id=object_id,
            # A named, non-thunk function at a concrete address is about as
            # solid as static analysis gets. The residual doubt is whether the
            # name came from symbols or from Ghidra's own heuristics.
            confidence=0.95,
            producer=producer,
            method="ghidra-function-recovery",
        )
        claims += 1
    return {"artifacts": artifacts, "claims": claims}


def _import_strings(
    rc: RunContext, object_id: str, export: dict[str, Any], producer: str
) -> int:
    count = 0
    for record in export.get("strings", []):
        text = sanitize_text(str(record.get("text") or ""), limit=MAX_STRING_LENGTH)
        if not text:
            continue
        data: dict[str, Any] = {
            "text": text,
            "encoding": str(record.get("encoding") or "unknown"),
            "length": len(text),
        }
        if record.get("addr") is not None:
            data["addr"] = int(record["addr"])
        if record.get("file_offset") is not None:
            data["file_offset"] = int(record["file_offset"])
        if record.get("section"):
            data["section"] = str(record["section"])
        if "addr" not in data and "file_offset" not in data:
            continue
        artifact = rc.artifact("string", data, object_id=object_id)
        count += 1

        # Same rules triage runs, but on strings Ghidra has located precisely.
        # When both engines see the same literal they attest to one claim, and
        # the confidence combiner treats that as corroboration.
        for detection in detectors.scan_secrets(text):
            rc.add_claim(
                "contains_hardcoded_secret",
                {
                    "secret_kind": detection.kind,
                    "detector": f"rule:{detection.rule_id}",
                    "redacted_preview": detection.matched,
                },
                [EvidenceRef(artifact.artifact_id, "locus")],
                subject_id=object_id,
                confidence=detection.confidence,
                producer=producer,
                method="string-pattern",
            )
        for detection in detectors.scan_components(text):
            statement: dict[str, Any] = {
                "component": detection.kind,
                "indicator": "version_banner",
            }
            if detection.extra.get("version"):
                statement["version"] = detection.extra["version"]
            rc.add_claim(
                "embeds_component",
                statement,
                [EvidenceRef(artifact.artifact_id, "locus")],
                subject_id=object_id,
                confidence=detection.confidence,
                producer=producer,
                method="version-banner",
            )
    return count


def _import_symbols(rc: RunContext, object_id: str, export: dict[str, Any]) -> int:
    count = 0
    for record in export.get("symbols", []):
        if record.get("addr") is None or not record.get("name"):
            continue
        rc.artifact(
            "symbol",
            _drop_none(
                {
                    "name": str(record["name"]),
                    "addr": int(record["addr"]),
                    "symbol_type": str(record.get("symbol_type") or "unknown"),
                    "namespace": _optional_text(record.get("namespace")),
                    "is_primary": bool(record.get("is_primary", False)),
                }
            ),
            object_id=object_id,
        )
        count += 1
    return count


def _import_xrefs(
    rc: RunContext, object_id: str, export: dict[str, Any], max_xrefs: int
) -> dict[str, Any]:
    """Store xrefs and index call sites by the name of what they call."""
    by_target_name: dict[str, list[str]] = {}
    count = 0
    for record in export.get("xrefs", []):
        if count >= max_xrefs:
            break
        if record.get("from_addr") is None or record.get("to_addr") is None:
            continue
        data = _drop_none(
            {
                "from_addr": int(record["from_addr"]),
                "to_addr": int(record["to_addr"]),
                "ref_type": str(record.get("ref_type") or "unknown"),
                "from_function": _optional_text(record.get("from_function")),
                "to_function": _optional_text(record.get("to_function")),
            }
        )
        artifact = rc.artifact("xref", data, object_id=object_id)
        count += 1
        target = str(record.get("to_function") or "")
        if target and data["ref_type"] == "call":
            bucket = by_target_name.setdefault(target.lstrip("_"), [])
            if len(bucket) < MAX_XREF_EVIDENCE:
                bucket.append(artifact.artifact_id)
    return {"count": count, "by_target_name": by_target_name}


def _import_decompilation(
    rc: RunContext, object_id: str, export: dict[str, Any]
) -> dict[str, str]:
    """Store decompiled function bodies; return function name -> artifact id."""
    by_function: dict[str, str] = {}
    for record in export.get("decompilation", []):
        code = str(record.get("code") or "")
        if not code or record.get("function_addr") is None:
            continue
        if len(code) > MAX_DECOMPILATION_CHARS:
            code = code[:MAX_DECOMPILATION_CHARS] + "\n/* truncated by Aether */\n"
        artifact = rc.artifact(
            "decompilation",
            {
                "function_addr": int(record["function_addr"]),
                "function_name": str(record.get("function_name") or "unknown"),
                "code": code,
                "decompiler": str(record.get("decompiler") or "ghidra"),
                "line_count": code.count("\n") + 1,
            },
            object_id=object_id,
        )
        by_function[str(record.get("function_name") or "")] = artifact.artifact_id
    return by_function


def _import_imports_exports(
    rc: RunContext,
    object_id: str,
    export: dict[str, Any],
    producer: str,
    call_sites: dict[str, list[str]],
    decompilation: dict[str, str],
) -> dict[str, int]:
    counts = {"imports": 0, "exports": 0, "import_claims": 0, "export_claims": 0}

    for record in export.get("imports", []):
        name = str(record.get("name") or "")
        if not name:
            continue
        data = _drop_none(
            {
                "name": name,
                "library": _optional_text(record.get("library")),
                "addr": _optional_int(record.get("addr")),
                "ordinal": _optional_int(record.get("ordinal")),
            }
        )
        artifact = rc.artifact("import", data, object_id=object_id)
        counts["imports"] += 1

        statement: dict[str, Any] = {"symbol": name}
        if data.get("library"):
            statement["library"] = data["library"]
        rc.add_claim(
            "imports_symbol",
            statement,
            [EvidenceRef(artifact.artifact_id, "locus")],
            subject_id=object_id,
            confidence=0.95,
            producer=producer,
            method="ghidra-symbol-table",
        )
        counts["import_claims"] += 1

        classification = detectors.classify_symbol(name)
        if classification is None:
            continue
        category, confidence = classification

        # This is what Ghidra buys over header parsing: not just that the
        # binary imports strcpy, but where it is called from, with the
        # decompiled body of the caller attached as corroboration.
        sites = call_sites.get(name.lstrip("_"), [])
        evidence = [EvidenceRef(artifact.artifact_id, "locus")]
        evidence.extend(EvidenceRef(site, "support") for site in sites[:MAX_XREF_EVIDENCE])
        caller_names = {
            str(x.get("from_function") or "")
            for x in export.get("xrefs", [])
            if str(x.get("to_function") or "").lstrip("_") == name.lstrip("_")
        }
        for caller in sorted(caller_names):
            decompiled_id = decompilation.get(caller)
            if decompiled_id:
                evidence.append(EvidenceRef(decompiled_id, "support"))

        risky_statement: dict[str, Any] = {"api": name, "category": category}
        if sites:
            risky_statement["call_site_count"] = len(sites)
        risky_claim = rc.add_claim(
            "uses_risky_api",
            risky_statement,
            evidence,
            subject_id=object_id,
            # Resolved call sites raise confidence that the API is genuinely
            # reachable rather than a leftover import.
            confidence=min(0.99, confidence + (0.05 if sites else 0.0)),
            producer=producer,
            method="ghidra-xref",
        )
        if sites:
            _link_refinement(rc, object_id, name, risky_claim.claim_id)

    for record in export.get("exports", []):
        name = str(record.get("name") or "")
        if not name or record.get("addr") is None:
            continue
        artifact = rc.artifact(
            "export", {"name": name, "addr": int(record["addr"])}, object_id=object_id
        )
        counts["exports"] += 1
        if _is_auto_named(name):
            continue
        rc.add_claim(
            "exports_symbol",
            {"symbol": name},
            [EvidenceRef(artifact.artifact_id, "locus")],
            subject_id=object_id,
            confidence=0.95,
            producer=producer,
            method="ghidra-symbol-table",
        )
        counts["export_claims"] += 1

    return counts


def _link_refinement(
    rc: RunContext, object_id: str, api: str, refined_claim_id: str
) -> None:
    """Link a call-site-backed claim to the coarser one it refines.

    Header parsing can only say "this binary imports strcpy". Ghidra can say
    where it is called from. Both are true and both are worth keeping - the
    coarse one because it holds even when disassembly fails - so rather than
    leaving two unrelated rows, the specific claim is recorded as *refining*
    the general one and a reviewer sees one lineage instead of two findings.
    """
    for existing in rc.project.find_claims(
        predicate="uses_risky_api", subject_id=object_id, limit=200
    ):
        if existing["id"] == refined_claim_id:
            continue
        if existing["statement"].get("api") != api:
            continue
        if existing["statement"].get("call_site_count"):
            continue
        rc.link_claims(refined_claim_id, existing["id"], "refines")


def summarize(export: dict[str, Any]) -> dict[str, Any]:
    """Human-facing summary of an export, used by the CLI."""
    meta = export.get("meta", {})
    return {
        "program": meta.get("program"),
        "format": meta.get("executable_format"),
        "language": meta.get("language_id"),
        "endian": meta.get("endian"),
        "image_base": meta.get("image_base"),
        "ghidra_version": meta.get("ghidra_version"),
        "counts": {stream: len(export.get(stream, [])) for stream in STREAMS},
    }


def _is_auto_named(name: str) -> bool:
    return any(name.startswith(prefix) for prefix in _AUTO_NAME_PREFIXES)


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = sanitize_text(str(value), limit=256)
    return text or None


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


__all__ = ["STREAMS", "import_export", "read_export", "summarize"]
