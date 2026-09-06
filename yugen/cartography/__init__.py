"""Firmware-scale relational analysis: links between binaries in one project.

Phase 2 of the specification is large - inter-binary maps, sink reachability
across files, version tracking, and diffing. This module is a first, honestly
scoped slice of it: it does not attempt full campaign tracking or
cross-binary sink reachability. What it does do is real and mechanical.

``link_imports`` resolves each file's imports against every other file's
exports in the same project, by name. That is the actual substance of an
inter-binary call graph: which binary's undefined symbol is satisfied by which
other binary's definition. It says nothing about whether the dependency is
actually loaded at runtime - dynamic linker search order, versioned symbols,
and preloading are all invisible to a name match - so the claim predicate's
own documentation says exactly that.

Nothing here infers anything from instruction bytes. It is a join over
symbol tables the adapters already recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yugen.evidence.models import EvidenceRef
from yugen.project.store import Project
from yugen.version import YUGEN_VERSION

#: Symbols exported by every libc/CRT on earth. Resolving against these tells a
#: reviewer nothing about this firmware's own structure, and at firmware scale
#: they would dominate the link count. Kept short and reversible: it trims
#: noise, it does not hide anything a claim would otherwise assert incorrectly.
_UBIQUITOUS_SYMBOLS = frozenset(
    {
        "malloc", "free", "calloc", "realloc", "memcpy", "memset", "memmove",
        "strlen", "strcmp", "strncmp", "printf", "fprintf", "sprintf", "snprintf",
        "open", "close", "read", "write", "exit", "abort", "main", "_start",
        "__libc_start_main", "__stack_chk_fail", "__errno_location",
    }
)


@dataclass
class CartographyResult:
    """What one linking pass found."""

    run_id: str
    files_considered: int = 0
    links_found: int = 0
    claims_written: int = 0
    claims_new: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "files_considered": self.files_considered,
            "links_found": self.links_found,
            "claims_written": self.claims_written,
            "claims_new": self.claims_new,
            "warnings": self.warnings,
        }


def link_imports(
    project: Project,
    *,
    ignore_ubiquitous: bool = True,
    min_confidence: float = 0.6,
) -> CartographyResult:
    """Resolve every file's imports against every other file's exports.

    A name match alone is not proof of a live dependency, so confidence is
    fixed at a level below what a header parse or a symbol table read earns
    elsewhere in Yugen - this is inference over two independent observations,
    not a direct reading of one file's own structure.
    """
    objects = project.objects()
    exporters: dict[str, list[tuple[Any, Any]]] = {}
    for obj in objects:
        for export in project.find_artifacts(
            kind="export", object_id=obj.artifact_id, limit=5000
        ):
            name = export.data.get("name")
            if isinstance(name, str) and name:
                exporters.setdefault(name, []).append((obj, export))
        # A dynamic symbol table entry with a defined address also counts as a
        # provider - PE binaries in particular often expose symbols this way
        # rather than through a distinct export artifact.
        for symbol in project.find_artifacts(
            kind="symbol", object_id=obj.artifact_id, limit=5000
        ):
            name = symbol.data.get("name")
            if isinstance(name, str) and name:
                exporters.setdefault(name, []).append((obj, symbol))

    warnings: list[str] = []
    if not exporters:
        warnings.append(
            "no export or symbol artifacts exist in this project; run Ghidra "
            "or triage over its binaries first, or every import will resolve "
            "to nothing"
        )

    with project.run(
        tool="yugen-cartography",
        tool_version=YUGEN_VERSION,
        adapter="cartography",
        params={"ignore_ubiquitous": ignore_ubiquitous, "min_confidence": min_confidence},
    ) as rc:
        links_found = 0
        for obj in objects:
            imports = project.find_artifacts(
                kind="import", object_id=obj.artifact_id, limit=5000
            )
            for imp in imports:
                name = imp.data.get("name")
                if not isinstance(name, str) or not name:
                    continue
                if ignore_ubiquitous and name.lstrip("_") in _UBIQUITOUS_SYMBOLS:
                    continue
                candidates = [
                    (provider, artifact)
                    for provider, artifact in exporters.get(name, [])
                    if provider.artifact_id != obj.artifact_id
                ]
                if not candidates:
                    continue

                # Multiple providers of the same symbol name is real and
                # ambiguous - record every candidate rather than guessing which
                # one the dynamic linker would actually pick.
                confidence = min_confidence if len(candidates) == 1 else min_confidence * 0.8
                for provider, export_artifact in candidates:
                    provider_path = str(
                        provider.data.get("path") or provider.name or provider.artifact_id
                    )
                    rc.add_claim(
                        "imports_resolved_by",
                        {"symbol": name, "provider_path": provider_path},
                        [
                            EvidenceRef(imp.artifact_id, "locus"),
                            EvidenceRef(export_artifact.artifact_id, "support"),
                        ],
                        subject_id=obj.artifact_id,
                        confidence=confidence,
                        producer="yugen-cartography",
                        method="symbol-name-match",
                    )
                    links_found += 1

        result = CartographyResult(
            run_id=rc.run.run_id,
            files_considered=len(objects),
            links_found=links_found,
            claims_written=rc.claims_written,
            claims_new=rc.claims_new,
            warnings=warnings,
        )
    return result


def dependency_graph(project: Project) -> dict[str, Any]:
    """Render the resolved links as a simple adjacency structure.

    Not a new query mechanism - it reads back exactly the
    ``imports_resolved_by`` claims :func:`link_imports` wrote, shaped for a
    caller that wants "what depends on what" rather than a claim list.
    """
    edges: list[dict[str, str]] = []
    for claim in project.find_claims(predicate="imports_resolved_by", limit=5000):
        subject = project.get_artifact(claim["subject_id"]) if claim["subject_id"] else None
        if subject is None:
            continue
        consumer_path = str(subject.data.get("path") or subject.name or subject.artifact_id)
        edges.append(
            {
                "consumer": consumer_path,
                "provider": str(claim["statement"]["provider_path"]),
                "symbol": str(claim["statement"]["symbol"]),
                "confidence": str(claim["confidence"]["combined"]),
            }
        )
    nodes = sorted({e["consumer"] for e in edges} | {e["provider"] for e in edges})
    return {"nodes": nodes, "edges": edges}


__all__ = ["CartographyResult", "dependency_graph", "link_imports"]
