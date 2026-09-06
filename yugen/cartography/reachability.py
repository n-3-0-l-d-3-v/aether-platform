"""Cross-binary sink reachability.

The piece of Phase 2's "sink reachability across files" that this codebase can
actually support without a multi-process emulator: chaining evidence that
already exists in the graph rather than observing anything new.

The chain is three claims deep, each already produced by an existing adapter:

1. ``function_reached`` (QEMU) - a function in file A was observed executing.
2. An ``xref`` artifact (Ghidra) - that function calls into an import.
3. ``imports_resolved_by`` (cartography linking) - that import is satisfied by
   an export in file B.

Put together: execution observed in A reaches the boundary of B, at the
symbol the export names. That is a real, evidenced statement about
cross-binary reachability - not a static "these binaries are connected"
assertion, but "this specific, observed code path gets there."

What this does not do: it does not trace *into* B. Nothing here claims that
B's implementation of the symbol was itself observed running, only that
control flow reaches the point where it would be called. A full call-stack
trace across a process boundary would need an emulator that can follow the
call there, which ``qemu-user`` - a single-process emulator - cannot do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yugen.evidence.models import EvidenceRef
from yugen.project.store import Project
from yugen.version import YUGEN_VERSION


@dataclass
class ReachabilityResult:
    """What one reachability pass found."""

    run_id: str
    functions_considered: int = 0
    sinks_reached: int = 0
    claims_written: int = 0
    claims_new: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "functions_considered": self.functions_considered,
            "sinks_reached": self.sinks_reached,
            "claims_written": self.claims_written,
            "claims_new": self.claims_new,
            "warnings": self.warnings,
        }


def trace_cross_binary_reachability(project: Project) -> ReachabilityResult:
    """Chain function_reached -> call xref -> imports_resolved_by into claims.

    Requires all three ingredients to already be in the project: a QEMU trace
    imported (for ``function_reached``), Ghidra results imported (for the
    xrefs that resolve a call to a named callee), and :func:`link_imports`
    already run (for ``imports_resolved_by``). Missing any one of them means
    zero sinks found, reported as a warning rather than an error - the
    prerequisites are optional analyses, not requirements of the project.
    """
    reached = project.find_claims(predicate="function_reached", limit=2000)
    links = project.find_claims(predicate="imports_resolved_by", limit=2000)

    warnings: list[str] = []
    if not reached:
        warnings.append(
            "no function_reached claims in this project; import a QEMU trace "
            "first, or there is no observed execution to chain from"
        )
    if not links:
        warnings.append(
            "no imports_resolved_by claims in this project; run 'yugen map' "
            "first, or there is nothing on the other side of any call"
        )

    # (importing_file_id, symbol) -> list of imports_resolved_by claims
    links_by_import: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for claim in links:
        key = (str(claim["subject_id"]), str(claim["statement"]["symbol"]))
        links_by_import.setdefault(key, []).append(claim)

    with project.run(
        tool="yugen-cartography", tool_version=YUGEN_VERSION, adapter="cartography-reach"
    ) as rc:
        sinks_found = 0
        considered = 0

        for claim in reached:
            file_id = claim["subject_id"]
            if not file_id:
                continue
            considered += 1
            function_name = str(claim["statement"]["name"])
            trace_hit_ids = [
                ref["artifact_id"] for ref in claim["evidence"] if ref["role"] == "support"
            ]
            function_ids = [
                ref["artifact_id"] for ref in claim["evidence"] if ref["role"] == "locus"
            ]
            if not function_ids:
                continue
            function_artifact = project.get_artifact(function_ids[0])
            if function_artifact is None:
                continue
            start = function_artifact.data.get("addr_start")
            end = function_artifact.data.get("addr_end") or (
                (start + (function_artifact.data.get("size") or 1)) if start is not None else None
            )
            if start is None or end is None:
                continue

            call_targets = {
                str(x.data.get("to_function"))
                for x in project.find_artifacts(kind="xref", object_id=file_id, limit=5000)
                if x.data.get("ref_type") == "call"
                and x.data.get("from_addr") is not None
                and start <= int(x.data["from_addr"]) < end
                and x.data.get("to_function")
            }
            call_xrefs = {
                str(x.data.get("to_function")): x
                for x in project.find_artifacts(kind="xref", object_id=file_id, limit=5000)
                if x.data.get("ref_type") == "call"
                and x.data.get("from_addr") is not None
                and start <= int(x.data["from_addr"]) < end
                and x.data.get("to_function") in call_targets
            }

            for symbol in call_targets:
                for link_claim in links_by_import.get((file_id, symbol), []):
                    provider_path = str(link_claim["statement"]["provider_path"])
                    sink_artifacts = [
                        ref["artifact_id"] for ref in link_claim["evidence"] if ref["role"] == "support"
                    ]
                    import_artifacts = [
                        ref["artifact_id"] for ref in link_claim["evidence"] if ref["role"] == "locus"
                    ]
                    if not sink_artifacts:
                        continue
                    sink_artifact = project.get_artifact(sink_artifacts[0])
                    if sink_artifact is None:
                        continue

                    evidence = [EvidenceRef(sink_artifacts[0], "locus")]
                    evidence.extend(EvidenceRef(i, "support") for i in trace_hit_ids[:5])
                    evidence.extend(EvidenceRef(i, "support") for i in import_artifacts[:1])
                    xref = call_xrefs.get(symbol)
                    if xref is not None:
                        evidence.append(EvidenceRef(xref.artifact_id, "support"))

                    # The chain is only as sound as its weakest link: an
                    # observed-execution claim and a name-match linking claim,
                    # combined. Taking the minimum, not the product, reflects
                    # that this is one reasoning chain rather than independent
                    # corroboration - the two halves are not corroborating the
                    # same fact, they are each necessary for a different part
                    # of it.
                    confidence = min(
                        claim["confidence"]["combined"], link_claim["confidence"]["combined"]
                    )

                    rc.add_claim(
                        "cross_binary_reachable",
                        {
                            "symbol": symbol,
                            "reached_via_file": str(
                                project.get_artifact(file_id).data.get("path")
                                or project.get_artifact(file_id).name
                                or file_id
                            ),
                            "reached_via_function": function_name,
                        },
                        evidence,
                        subject_id=sink_artifact.object_id or link_claim["subject_id"],
                        confidence=confidence,
                        producer="yugen-cartography",
                        method="reach-via-import-link",
                    )
                    sinks_found += 1

        result = ReachabilityResult(
            run_id=rc.run.run_id,
            functions_considered=considered,
            sinks_reached=sinks_found,
            claims_written=rc.claims_written,
            claims_new=rc.claims_new,
            warnings=warnings,
        )
    return result


__all__ = ["ReachabilityResult", "trace_cross_binary_reachability"]
