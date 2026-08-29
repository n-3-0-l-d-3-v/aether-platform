"""Triage adapter: header identification, strings, and mechanical detectors.

Runs everywhere, needs nothing installed, and produces the baseline every other
adapter builds on. When Ghidra later analyses the same file it converges onto
these artifact ids rather than duplicating them, because both derive identity
from the same addresses and text.
"""

from __future__ import annotations

import os
from typing import Any

from aether.adapters.base import Adapter, AdapterResult, Availability
from aether.adapters.triage import detectors, formats, strings
from aether.evidence.models import EvidenceRef
from aether.project.store import Project
from aether.util import sanitize_text
from aether.version import AETHER_VERSION

#: Cap on string artifacts per file. Firmware blobs can yield hundreds of
#: thousands of strings, almost all noise; the interesting ones are the ones a
#: detector fires on, and those are always kept regardless of this cap.
DEFAULT_STRING_LIMIT = 3000

#: Strings longer than this are truncated before storage.
MAX_STRING_LENGTH = 512

#: Cap on indicator-grade claims of one category per file. Secrets and
#: components are never capped; those are findings, and there are few of them.
MAX_SUSPICIOUS_PER_CATEGORY = 20


class TriageAdapter(Adapter):
    """Header-level analysis and rule-based claim production."""

    name = "triage"
    tool = "aether-triage"

    def probe(self) -> Availability:
        return Availability(
            available=True,
            version=AETHER_VERSION,
            detail="built in; no external engine required",
        )

    def triage_into(
        self,
        rc: Any,
        project: Project,
        target: str,
        *,
        logical_path: str | None = None,
        source: str = "ingest",
        parent_id: str | None = None,
        string_limit: int = DEFAULT_STRING_LIMIT,
        min_string_length: int = strings.DEFAULT_MIN_LENGTH,
        emit_strings: bool = True,
    ) -> tuple[Any, formats.Identification, dict[str, Any]]:
        """Triage one file into an *existing* run.

        Split out from :meth:`analyze` so the firmware extractor can triage
        every carved file inside its own single run. SQLite has no nested
        transactions, so an adapter that called ``analyze`` per extracted file
        would either fail outright or scatter one logical extraction across
        hundreds of runs.
        """
        from aether.adapters.ingest import ingest_file

        artifact, ident = ingest_file(
            rc,
            project,
            target,
            logical_path=logical_path,
            source=source,
            parent_id=parent_id,
            producer=self.tool,
        )
        object_id = artifact.artifact_id

        for warning in ident.warnings:
            rc.annotate("artifact", object_id, f"triage warning: {warning}", author=self.tool)

        self._record_sections(rc, object_id, ident)
        symbol_artifacts = self._record_symbols(rc, object_id, ident)
        self._record_hardening(rc, object_id, ident)
        self._record_risky_apis(rc, object_id, ident, symbol_artifacts)

        string_stats = {"scanned": 0, "stored": 0}
        if emit_strings and ident.format != "compressed":
            string_stats = self._record_strings(
                rc, object_id, target, ident, string_limit, min_string_length
            )

        details = {
            "path": artifact.data.get("path"),
            "format": ident.format,
            "media_type": ident.media_type,
            "arch": ident.arch,
            "bits": ident.bits,
            "sections": len(ident.sections),
            "imports": len(ident.imports),
            "exports": len(ident.exports),
            "strings_scanned": string_stats["scanned"],
            "strings_stored": string_stats["stored"],
        }
        return artifact, ident, details

    def analyze(
        self,
        project: Project,
        target: str,
        *,
        logical_path: str | None = None,
        source: str = "ingest",
        parent_id: str | None = None,
        string_limit: int = DEFAULT_STRING_LIMIT,
        min_string_length: int = strings.DEFAULT_MIN_LENGTH,
        emit_strings: bool = True,
    ) -> AdapterResult:
        """Ingest and triage one file in a run of its own."""
        with project.run(
            tool=self.tool,
            tool_version=AETHER_VERSION,
            adapter=self.name,
            params={
                "string_limit": string_limit,
                "min_string_length": min_string_length,
                "emit_strings": emit_strings,
            },
            input_digest=_quick_digest(target),
        ) as rc:
            artifact, ident, details = self.triage_into(
                rc,
                project,
                target,
                logical_path=logical_path,
                source=source,
                parent_id=parent_id,
                string_limit=string_limit,
                min_string_length=min_string_length,
                emit_strings=emit_strings,
            )
            details["field_conflicts"] = rc.field_conflicts
            result = AdapterResult(
                adapter=self.name,
                run_id=rc.run.run_id,
                artifacts=rc.artifacts_written,
                artifacts_new=rc.artifacts_new,
                claims=rc.claims_written,
                claims_new=rc.claims_new,
                objects=[artifact.artifact_id],
                warnings=list(ident.warnings),
                details=details,
            )
        return result

    # -- record helpers --------------------------------------------------

    def _record_sections(self, rc: Any, object_id: str, ident: formats.Identification) -> None:
        for section in ident.sections:
            rc.artifact("section", section.to_data(), object_id=object_id)

    def _record_symbols(
        self, rc: Any, object_id: str, ident: formats.Identification
    ) -> dict[str, str]:
        """Store imports, exports, and symbols; return name -> artifact id."""
        by_name: dict[str, str] = {}
        for entry in ident.imports:
            data: dict[str, Any] = {"name": entry["name"]}
            if entry.get("library"):
                data["library"] = entry["library"]
            if entry.get("addr"):
                data["addr"] = entry["addr"]
            if entry.get("ordinal") is not None:
                data["ordinal"] = entry["ordinal"]
            artifact = rc.artifact("import", data, object_id=object_id)
            by_name.setdefault(entry["name"], artifact.artifact_id)

        for entry in ident.exports:
            artifact = rc.artifact(
                "export",
                {"name": entry["name"], "addr": entry.get("addr", 0)},
                object_id=object_id,
            )
            by_name.setdefault(entry["name"], artifact.artifact_id)

        for entry in ident.symbols:
            rc.artifact(
                "symbol",
                {
                    "name": entry["name"],
                    "addr": entry.get("addr", 0),
                    "symbol_type": entry.get("symbol_type", "unknown"),
                },
                object_id=object_id,
            )
        return by_name

    def _record_hardening(
        self, rc: Any, object_id: str, ident: formats.Identification
    ) -> None:
        for feature, present in sorted(ident.hardening.items()):
            evidence = [EvidenceRef(object_id, "locus")]
            rc.add_claim(
                "binary_hardening",
                {"feature": feature, "present": bool(present)},
                evidence,
                subject_id=object_id,
                # Read straight out of a header field or segment table. The
                # residual uncertainty is in what the flag *implies* at runtime,
                # not in whether the bit is set.
                confidence=0.9,
                producer=self.tool,
                method="header-flags",
            )

    def _record_risky_apis(
        self,
        rc: Any,
        object_id: str,
        ident: formats.Identification,
        symbol_artifacts: dict[str, str],
    ) -> None:
        names = [entry["name"] for entry in ident.imports] + [
            entry["name"] for entry in ident.symbols
        ]
        for name, (category, confidence) in sorted(detectors.classify_symbols(names).items()):
            locus = symbol_artifacts.get(name)
            if locus is None:
                continue
            rc.add_claim(
                "uses_risky_api",
                {"api": name, "category": category},
                [EvidenceRef(locus, "locus")],
                subject_id=object_id,
                confidence=confidence,
                producer=self.tool,
                method="symbol-table-rule",
            )

    def _record_strings(
        self,
        rc: Any,
        object_id: str,
        target: str,
        ident: formats.Identification,
        string_limit: int,
        min_string_length: int,
    ) -> dict[str, int]:
        """Store strings, prioritising any that a detector fires on.

        Detector hits are stored unconditionally. The cap applies only to the
        remainder, so raising or lowering it never changes which claims exist -
        only how much surrounding context is retained.
        """
        extracted = strings.extract_from_file(target, min_length=min_string_length)
        section_lookup = _section_lookup(ident.sections)

        interesting: list[
            tuple[strings.ExtractedString, list[Any], list[Any], list[Any]]
        ] = []
        plain: list[strings.ExtractedString] = []
        suspicious_budget = dict.fromkeys(
            {rule.category for rule in detectors.SUSPICIOUS_RULES},
            MAX_SUSPICIOUS_PER_CATEGORY,
        )
        for item in extracted:
            secrets = list(detectors.scan_secrets(item.text))
            components = list(detectors.scan_components(item.text))
            # Indicator-grade detections are capped per category per file. A
            # binary with four hundred URLs in it is one observation about that
            # binary; four hundred claims would bury the findings that matter
            # and cost the reviewer exactly the precision this layer is for.
            suspicious = [
                detection
                for detection in detectors.scan_suspicious(item.text)
                if suspicious_budget.get(detection.kind, 0) > 0
            ]
            for detection in suspicious:
                suspicious_budget[detection.kind] -= 1
            if secrets or components or suspicious:
                interesting.append((item, secrets, components, suspicious))
            else:
                plain.append(item)

        stored = 0
        for item, secrets, components, suspicious in interesting:
            artifact_id = self._store_string(rc, object_id, item, section_lookup)
            stored += 1
            for detection in secrets:
                rc.add_claim(
                    "contains_hardcoded_secret",
                    {
                        "secret_kind": detection.kind,
                        "detector": f"rule:{detection.rule_id}",
                        "redacted_preview": detection.matched,
                    },
                    [EvidenceRef(artifact_id, "locus")],
                    subject_id=object_id,
                    confidence=detection.confidence,
                    producer=self.tool,
                    method="string-pattern",
                )
            for detection in components:
                statement: dict[str, Any] = {
                    "component": detection.kind,
                    "indicator": "version_banner",
                }
                if detection.extra.get("version"):
                    statement["version"] = detection.extra["version"]
                rc.add_claim(
                    "embeds_component",
                    statement,
                    [EvidenceRef(artifact_id, "locus")],
                    subject_id=object_id,
                    confidence=detection.confidence,
                    producer=self.tool,
                    method="version-banner",
                )
            for detection in suspicious:
                rc.add_claim(
                    "suspicious_string",
                    {
                        "category": detection.kind,
                        "detector": f"rule:{detection.rule_id}",
                        "preview": detection.matched,
                    },
                    [EvidenceRef(artifact_id, "locus")],
                    subject_id=object_id,
                    confidence=detection.confidence,
                    producer=self.tool,
                    method="string-pattern",
                )

        budget = max(0, string_limit - stored)
        for item in plain[:budget]:
            self._store_string(rc, object_id, item, section_lookup)
            stored += 1

        return {"scanned": len(extracted), "stored": stored}

    def _store_string(
        self,
        rc: Any,
        object_id: str,
        item: strings.ExtractedString,
        section_lookup: Any,
    ) -> str:
        data = item.to_data()
        data["text"] = sanitize_text(str(data["text"]), limit=MAX_STRING_LENGTH)
        placement = section_lookup(item.file_offset)
        if placement is not None:
            name, virtual_address = placement
            data["section"] = name
            # Translating the file offset into a virtual address is what lets
            # this observation converge with Ghidra's, which only ever reports
            # addresses. Without it the same literal would occupy two artifacts.
            if virtual_address is not None:
                data["addr"] = virtual_address
        artifact = rc.artifact("string", data, object_id=object_id)
        return artifact.artifact_id


def _section_lookup(sections: list[formats.Section]) -> Any:
    """Map a file offset to its section name and virtual address.

    Attaching a string to its section is what lets a reviewer tell a hardcoded
    key in ``.rodata`` from a coincidental byte run inside compressed data.
    """
    ranges = sorted(
        (
            section.file_offset,
            section.file_offset + max(0, section.addr_end - section.addr_start),
            section.name,
            section.addr_start,
        )
        for section in sections
        if section.initialized and section.addr_end > section.addr_start
    )

    def lookup(offset: int) -> tuple[str, int | None] | None:
        for start, end, name, addr_start in ranges:
            if start <= offset < end:
                virtual = addr_start + (offset - start) if addr_start else None
                return name, virtual
        return None

    return lookup


def _quick_digest(path: str) -> str:
    """Cheap identity for a run's input, recorded in provenance."""
    try:
        stat = os.stat(path)
    except OSError:
        return ""
    return f"{os.path.basename(path)}:{stat.st_size}"


def probe() -> Availability:
    return TriageAdapter().probe()


__all__ = ["TriageAdapter", "detectors", "formats", "strings", "probe"]
