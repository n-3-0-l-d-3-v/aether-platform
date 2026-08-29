"""Answer types for the narrow natural-language interface.

The specification permits free text in exactly one place: "explanations that
reference Claim IDs". This module makes that the only representable shape.

An :class:`Answer` is not a paragraph. It is a list of :class:`AnswerLine`,
and every line either cites at least one claim id or is explicitly marked as a
caveat. :func:`validate_answer` enforces that, and a test asserts it holds for
every question type against real projects. A sentence that asserts something
about a binary without naming the evidence for it cannot be constructed here.

That constraint is what keeps this layer honest. The prose is assembled from
templates over claim data the deterministic engines produced; nothing in this
package invents a finding, and nothing calls a language model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aether.errors import AetherError


class AnswerError(AetherError):
    """An answer was constructed in a shape the evidence model forbids."""

    exit_code = 9


@dataclass(frozen=True)
class Finding:
    """One claim, resolved enough to be shown to a person."""

    claim_id: str
    predicate: str
    statement: dict[str, Any]
    confidence: float
    producers: tuple[str, ...]
    subject_path: str | None
    #: Where the evidence physically is: artifact id, kind, and location.
    evidence: tuple[dict[str, Any], ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "predicate": self.predicate,
            "statement": self.statement,
            "confidence": self.confidence,
            "producers": list(self.producers),
            "subject_path": self.subject_path,
            "evidence": [dict(e) for e in self.evidence],
        }


@dataclass(frozen=True)
class AnswerLine:
    """One sentence of an explanation, bound to the claims it rests on."""

    text: str
    claim_ids: tuple[str, ...] = ()
    #: A caveat states a limit of the analysis, not a fact about the binary, so
    #: it is the one line type permitted to cite nothing.
    is_caveat: bool = False

    def to_record(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "claim_ids": list(self.claim_ids),
            "is_caveat": self.is_caveat,
        }


@dataclass
class Answer:
    """The result of asking one supported question."""

    question: str
    question_type: str | None
    understood: bool
    match_confidence: float
    lines: list[AnswerLine] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    #: Populated only when the question was not understood.
    supported: list[dict[str, str]] = field(default_factory=list)
    scope: str | None = None

    @property
    def claim_ids(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.claim_id not in seen:
                seen.append(finding.claim_id)
        return seen

    def to_record(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "question_type": self.question_type,
            "understood": self.understood,
            "match_confidence": round(self.match_confidence, 4),
            "scope": self.scope,
            "lines": [line.to_record() for line in self.lines],
            "findings": [f.to_record() for f in self.findings],
            "caveats": list(self.caveats),
            "supported": list(self.supported),
            "claim_ids": self.claim_ids,
        }

    def render(self) -> str:
        """Plain-text rendering, with citations kept visible."""
        out: list[str] = []
        for line in self.lines:
            if line.claim_ids:
                citation = ", ".join(cid[:16] for cid in line.claim_ids[:4])
                if len(line.claim_ids) > 4:
                    citation += f", +{len(line.claim_ids) - 4} more"
                out.append(f"{line.text}  [{citation}]")
            else:
                out.append(line.text)
        for caveat in self.caveats:
            out.append(f"  caveat: {caveat}")
        return "\n".join(out)


def validate_answer(answer: Answer) -> None:
    """Enforce the citation invariant, or raise :class:`AnswerError`.

    Called on every answer before it leaves the package. It is cheap, and it is
    the difference between "we intend not to emit unevidenced prose" and "we
    cannot".
    """
    known = set(answer.claim_ids)
    for line in answer.lines:
        if line.is_caveat:
            if line.claim_ids:
                raise AnswerError(
                    "a caveat states a limit of the analysis and must not cite "
                    f"claims: {line.text!r}"
                )
            continue
        if not line.claim_ids:
            raise AnswerError(
                "every explanatory line must cite at least one claim id; "
                f"this one cites none: {line.text!r}"
            )
        unknown = [cid for cid in line.claim_ids if cid not in known]
        if unknown:
            raise AnswerError(
                f"line cites claim id(s) not among the answer's findings: {unknown}"
            )


__all__ = [
    "Answer",
    "AnswerError",
    "AnswerLine",
    "Finding",
    "validate_answer",
]
