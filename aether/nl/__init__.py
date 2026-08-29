"""Narrow natural-language interface over the evidence graph.

One entry point, :func:`ask`. It classifies a question into one of five
supported types, runs that type's deterministic query over the graph, and
returns an :class:`~aether.nl.model.Answer` whose every explanatory line cites
the claims it rests on.

What this is not: a language model, a chat interface, or a general question
answerer. It contains no model call and makes no network request. A question it
does not recognise comes back declined, with the supported set listed. That
narrowness is the design - it is what makes precision measurable, which is the
Phase 1 requirement the interface exists to satisfy.
"""

from __future__ import annotations

from typing import Any

from aether.errors import EvidenceError
from aether.nl.model import Answer, AnswerError, AnswerLine, Finding, validate_answer
from aether.nl.questions import (
    MATCH_THRESHOLD,
    QUESTION_TYPES,
    PlanContext,
    QuestionType,
    classify,
    describe_supported,
    score_all,
)
from aether.project.store import Project
from aether.util import hex_addr

#: Cap on claims pulled per predicate. An answer is a summary; a reviewer who
#: wants every row uses `aether query claims`.
DEFAULT_CLAIM_LIMIT = 400


def ask(
    project: Project,
    question: str,
    *,
    object_reference: str | None = None,
    limit: int = DEFAULT_CLAIM_LIMIT,
) -> Answer:
    """Answer one question from the evidence graph, or decline it."""
    question = (question or "").strip()
    if not question:
        raise EvidenceError("ask what? the question was empty")

    question_type, score = classify(question)
    scope_label: str | None = None
    object_id: str | None = None

    if object_reference:
        subject = project.resolve_object(object_reference)
        if subject is None:
            raise EvidenceError(
                f"no file in this project matches {object_reference!r}"
            )
        object_id = subject.artifact_id
        scope_label = str(subject.data.get("path") or subject.name or object_reference)

    if question_type is None:
        answer = Answer(
            question=question,
            question_type=None,
            understood=False,
            match_confidence=score,
            lines=[
                AnswerLine(
                    "That is outside the set of questions this interface "
                    "answers, so it was not guessed at.",
                    is_caveat=True,
                )
            ],
            caveats=[
                "Phase 1 supports a deliberately narrow set of question types "
                "so that its precision can be measured."
            ],
            supported=describe_supported(),
            scope=scope_label,
        )
        validate_answer(answer)
        return answer

    findings = _collect(project, question_type, object_id, limit)
    context = PlanContext(
        project=project, object_id=object_id, scope_label=scope_label
    )
    lines, caveats = question_type.summarize(findings, context)

    answer = Answer(
        question=question,
        question_type=question_type.id,
        understood=True,
        match_confidence=score,
        lines=lines,
        findings=findings,
        caveats=caveats,
        scope=scope_label,
    )
    validate_answer(answer)
    return answer


def _collect(
    project: Project,
    question_type: QuestionType,
    object_id: str | None,
    limit: int,
) -> list[Finding]:
    """Fetch and resolve the claims that answer this question type."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for predicate in question_type.predicates:
        claims = project.find_claims(
            predicate=predicate,
            subject_id=object_id,
            min_confidence=question_type.min_confidence or None,
            limit=limit,
        )
        for claim in claims:
            if claim["id"] in seen:
                continue
            seen.add(claim["id"])
            findings.append(_resolve(project, claim))

    findings.sort(key=lambda f: (-f.confidence, f.predicate, f.claim_id))
    return findings


def _resolve(project: Project, claim: dict[str, Any]) -> Finding:
    """Turn a stored claim into a Finding, with its evidence located."""
    subject_path: str | None = None
    if claim.get("subject_id"):
        subject = project.get_artifact(claim["subject_id"])
        if subject is not None:
            subject_path = str(subject.data.get("path") or subject.name or "")

    evidence: list[dict[str, Any]] = []
    for ref in claim.get("evidence", []):
        artifact = project.get_artifact(ref["artifact_id"])
        if artifact is None:
            continue
        evidence.append(
            {
                "artifact_id": artifact.artifact_id,
                "kind": artifact.kind,
                "role": ref.get("role", "locus"),
                "location": _locate(artifact),
            }
        )

    return Finding(
        claim_id=claim["id"],
        predicate=claim["predicate"],
        statement=dict(claim["statement"]),
        confidence=float(claim["confidence"]["combined"]),
        producers=tuple(sorted(claim["confidence"]["per_producer"])),
        subject_path=subject_path,
        evidence=tuple(evidence),
    )


def _locate(artifact: Any) -> str:
    """Human-readable position of an artifact inside its file."""
    data = artifact.data
    if data.get("addr") is not None:
        where = hex_addr(int(data["addr"]))
        section = data.get("section")
        return f"{where} in {section}" if section else where
    if data.get("addr_start") is not None:
        return hex_addr(int(data["addr_start"]))
    if data.get("file_offset") is not None:
        return f"offset {int(data['file_offset'])}"
    if data.get("path"):
        return str(data["path"])
    return "an unrecorded location"


__all__ = [
    "Answer",
    "AnswerError",
    "AnswerLine",
    "Finding",
    "MATCH_THRESHOLD",
    "QUESTION_TYPES",
    "ask",
    "classify",
    "describe_supported",
    "score_all",
    "validate_answer",
]
