"""Approval workflow: a human review queue over agent-submitted claims.

The specification's Phase 3 asks for "approval workflows" alongside "full
specialist agents." The evidence model already carries everything this needs:
a claim's ``status`` field (``proposed`` / ``accepted`` / ``rejected`` /
``superseded``), and the fact that an MCP-submitted claim is attested with
``producer_kind="agent"`` and starts life as ``proposed`` (see
:mod:`yugen.mcp.tools`). What did not exist was a queue: a way to see what is
waiting, and a recorded act of a human deciding on it.

That is all this module is. It does not run anything, does not call a model,
and does not change what a claim asserts - only its curation status, plus an
annotation recording who decided and why. The annotation is free text, and
that is fine: a reviewer's note about *why* they approved or rejected a claim
is exactly the kind of commentary annotations exist for (ADR-adjacent to
Phase 0's "no field of type prose on any predicate" - the claim itself is
never touched).

Deliberately absent: any way for an agent to approve or reject through MCP.
Only :func:`pending` is exposed there. Agents propose; only a human, acting
through the CLI, can promote a proposal to accepted. An approval tool sitting
next to the submission tool would let an agent mark its own homework, which is
the exact failure "approval workflow" exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yugen.errors import EvidenceError
from yugen.project.store import Project


@dataclass(frozen=True)
class PendingClaim:
    """One claim awaiting human review, with enough context to decide on it."""

    claim_id: str
    predicate: str
    statement: dict[str, Any]
    confidence: float
    producers: tuple[str, ...]
    subject_path: str | None
    evidence_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "predicate": self.predicate,
            "statement": self.statement,
            "confidence": self.confidence,
            "producers": list(self.producers),
            "subject_path": self.subject_path,
            "evidence_count": self.evidence_count,
        }


@dataclass
class Decision:
    """The result of approving or rejecting one claim."""

    claim_id: str
    outcome: str  # "accepted" or "rejected"
    reviewer: str
    annotation_id: str
    note: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "outcome": self.outcome,
            "reviewer": self.reviewer,
            "annotation_id": self.annotation_id,
            "note": self.note,
        }


def pending(
    project: Project,
    *,
    agent_only: bool = True,
    predicate: str | None = None,
    min_confidence: float | None = None,
    limit: int = 100,
) -> list[PendingClaim]:
    """List claims awaiting review.

    ``agent_only`` (the default) restricts the queue to claims with at least
    one ``agent`` attestation - the case "approval workflow" exists for. A
    tool's own proposed claims are set to ``agent_only=False`` to include, but
    a project running only deterministic adapters has no queue at all by
    default, which is correct: nothing needs a human's approval until an agent
    has proposed something.
    """
    claims = project.find_claims(
        predicate=predicate,
        status="proposed",
        min_confidence=min_confidence,
        limit=limit,
    )
    out: list[PendingClaim] = []
    for claim in claims:
        producer_kinds = {a["producer_kind"] for a in claim["attestations"]}
        if agent_only and "agent" not in producer_kinds:
            continue
        subject_path = None
        if claim.get("subject_id"):
            subject = project.get_artifact(claim["subject_id"])
            if subject is not None:
                subject_path = subject.data.get("path") or subject.name
        out.append(
            PendingClaim(
                claim_id=claim["id"],
                predicate=claim["predicate"],
                statement=claim["statement"],
                confidence=claim["confidence"]["combined"],
                producers=tuple(sorted(claim["confidence"]["per_producer"])),
                subject_path=subject_path,
                evidence_count=len(claim["evidence"]),
            )
        )
    return out


def _decide(
    project: Project, claim_id: str, outcome: str, *, reviewer: str, note: str
) -> Decision:
    resolved_id = project.resolve_id(claim_id) or claim_id
    claim = project.get_claim(resolved_id)
    if claim is None:
        raise EvidenceError(f"unknown claim {claim_id}")
    if claim["status"] != "proposed":
        raise EvidenceError(
            f"claim {resolved_id} is already {claim['status']!r}; only a "
            "proposed claim can be reviewed"
        )

    project.set_claim_status(resolved_id, outcome)
    body = f"{outcome} by {reviewer}"
    if note:
        body += f": {note}"
    with project.run(
        tool="yugen-review", tool_version="1", adapter="review", params={"outcome": outcome}
    ) as rc:
        annotation_id = rc.annotate("claim", resolved_id, body, author=reviewer)

    return Decision(
        claim_id=resolved_id, outcome=outcome, reviewer=reviewer, annotation_id=annotation_id, note=note
    )


def approve(project: Project, claim_id: str, *, reviewer: str, note: str = "") -> Decision:
    """Promote a proposed claim to accepted, with an audit trail."""
    return _decide(project, claim_id, "accepted", reviewer=reviewer, note=note)


def reject(project: Project, claim_id: str, *, reviewer: str, note: str = "") -> Decision:
    """Reject a proposed claim, with an audit trail."""
    return _decide(project, claim_id, "rejected", reviewer=reviewer, note=note)


__all__ = ["Decision", "PendingClaim", "approve", "pending", "reject"]
