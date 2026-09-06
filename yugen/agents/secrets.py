"""Secrets/indicators triage agent.

Supplements :mod:`yugen.adapters.triage.detectors` - the deterministic,
regex-based secret and suspicious-string rules - with a local LLM's judgment
over the same string evidence. The deterministic rules are precise but rigid:
they catch an AWS key id or a PEM header exactly, and miss anything shaped
differently - an obfuscated credential, a password split across concatenated
literals, a connection string with unusual punctuation. This agent reads the
string text an LLM might recognise as credential- or indicator-shaped even
though no fixed pattern matched it.

Three properties hold no matter what the model says:

1. **Never bypasses human review.** Every claim this agent proposes is
   submitted with ``producer_kind="agent"``, which means it lands with
   ``status="proposed"`` (see :mod:`yugen.project.store` and
   :mod:`yugen.review`) - identical to any other agent-attested claim. There
   is no path from here to ``accepted`` that does not go through a human
   running ``yugen review approve``. See ADR 0009 for why that boundary is
   enforced by never exposing approval over MCP, and ADR 0010 for why this
   agent gets no special trust either.
2. **Local-only backend is a hard boundary, not a default.** The caller must
   construct and pass an :class:`~yugen.agents.backend.LLMBackend`; nothing
   here reaches out to a cloud API, and nothing here silently falls back to
   one. See :mod:`yugen.agents.backend`.
3. **Its output is noisier than the deterministic rules', on purpose.** An
   LLM is asked for judgment, not a fixed pattern match, so false positives
   are expected. That is exactly why proposals from this agent get zero
   special trust in the review queue: they compete for a reviewer's attention
   like anything else an agent submits, never more.

This agent only ever runs when a human explicitly invokes
``yugen agent secrets`` (or calls :func:`run_secrets_triage` directly). Nothing
in ``yugen analyze`` or any adapter calls it implicitly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from yugen.agents.backend import LLMBackend
from yugen.evidence.models import EvidenceRef
from yugen.project.store import Project
from yugen.util import redact, sanitize_text
from yugen.version import YUGEN_VERSION

#: Tool/producer identity recorded in provenance and attestations.
TOOL_NAME = "yugen-agent-secrets"

#: Enum values a valid LLM item may name, per predicate. Kept in lockstep with
#: yugen.evidence.schemas.CLAIM_PREDICATES; this module never adds to either.
SECRET_KINDS: tuple[str, ...] = (
    "private_key",
    "certificate",
    "aws_access_key",
    "api_token",
    "password",
    "ssh_authorized_key",
    "jwt",
    "connection_string",
    "unknown",
)

SUSPICIOUS_CATEGORIES: tuple[str, ...] = (
    "url",
    "ip_address",
    "shell_command",
    "device_path",
    "debug_interface",
    "encoded_blob",
    "sql_fragment",
)

#: How much of a candidate string's own text is shown to the model. Long
#: enough for context, short enough that a batch of twenty stays a reasonable
#: prompt size.
CANDIDATE_PREVIEW_LENGTH = 200

#: How much of a flagged string is kept in the claim's own preview field.
CLAIM_PREVIEW_LENGTH = 80


@dataclass(frozen=True)
class AgentRunResult:
    """What one call to :func:`run_secrets_triage` accomplished."""

    proposed_claim_ids: tuple[str, ...]
    considered: int
    skipped_existing: int
    skipped_low_confidence: int
    skipped_malformed: int

    def to_record(self) -> dict[str, Any]:
        return {
            "proposed_claim_ids": list(self.proposed_claim_ids),
            "proposed": len(self.proposed_claim_ids),
            "considered": self.considered,
            "skipped_existing": self.skipped_existing,
            "skipped_low_confidence": self.skipped_low_confidence,
            "skipped_malformed": self.skipped_malformed,
        }


def _already_claimed(project: Project, artifact_id: str) -> bool:
    """True when a secret/suspicious claim already cites this string.

    Avoids proposing a duplicate for a candidate the deterministic rules, or
    an earlier agent run, already flagged.
    """
    for predicate in ("contains_hardcoded_secret", "suspicious_string"):
        if project.find_claims(predicate=predicate, artifact_id=artifact_id, limit=1):
            return True
    return False


def _candidate_strings(project: Project, object_id: str | None) -> tuple[list[Any], int]:
    """Return ``(candidates, skipped_existing)``.

    A candidate already cited by a ``contains_hardcoded_secret`` or
    ``suspicious_string`` claim - from the deterministic rules or an earlier
    agent run - is counted as skipped rather than re-proposed.
    """
    candidates: list[Any] = []
    skipped = 0
    for artifact in project.find_artifacts(kind="string", object_id=object_id, limit=5000):
        if _already_claimed(project, artifact.artifact_id):
            skipped += 1
            continue
        candidates.append(artifact)
    return candidates, skipped


def _build_prompt(batch: list[tuple[int, Any]]) -> str:
    lines = [
        "You are assisting a binary/firmware analysis tool by looking for "
        "hardcoded secrets and suspicious indicator strings that a simple "
        "pattern-matcher would plausibly miss - do not flag obvious cases "
        "a regex would already catch (a labelled PEM header, an "
        "unmistakable AWS key id, and so on).",
        "",
        "For each numbered string below, decide whether it is worth a "
        "reviewer's attention as either:",
        f"  - contains_hardcoded_secret, with a kind from exactly: "
        f"{', '.join(SECRET_KINDS)}",
        f"  - suspicious_string, with a kind from exactly: "
        f"{', '.join(SUSPICIOUS_CATEGORIES)}",
        "",
        "Respond with STRICT JSON ONLY: a list of objects, each "
        '{"index": <int>, "predicate": "contains_hardcoded_secret" | '
        '"suspicious_string", "kind": "<one of the values above>", '
        '"confidence": <number 0-1>}. Include only strings worth flagging. '
        "If none qualify, respond with an empty list: []. No prose, no "
        "markdown fences, nothing but the JSON list.",
        "",
        "Strings:",
    ]
    for index, artifact in batch:
        text = sanitize_text(str(artifact.data.get("text", "")), limit=CANDIDATE_PREVIEW_LENGTH)
        lines.append(f"{index}: {text}")
    return "\n".join(lines)


def _parse_items(raw: str, batch_size: int) -> tuple[list[dict[str, Any]], int]:
    """Defensively parse the model's response.

    Returns ``(valid_items, malformed_count)``. A whole response that fails to
    parse as JSON, or that is not a list, counts as one malformed batch (with
    ``malformed_count`` set to the batch size, so the caller's accounting
    reflects every candidate the batch could have covered). Individual
    malformed entries inside an otherwise-valid list are skipped one at a
    time.
    """
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return [], batch_size
    if not isinstance(parsed, list):
        return [], batch_size

    valid: list[dict[str, Any]] = []
    malformed = 0
    for item in parsed:
        if not isinstance(item, dict):
            malformed += 1
            continue
        index = item.get("index")
        predicate = item.get("predicate")
        kind = item.get("kind")
        confidence = item.get("confidence")
        if not isinstance(index, int) or index < 0 or index >= batch_size:
            malformed += 1
            continue
        if predicate not in ("contains_hardcoded_secret", "suspicious_string"):
            malformed += 1
            continue
        allowed_kinds = SECRET_KINDS if predicate == "contains_hardcoded_secret" else SUSPICIOUS_CATEGORIES
        if not isinstance(kind, str) or kind not in allowed_kinds:
            malformed += 1
            continue
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            malformed += 1
            continue
        valid.append(
            {
                "index": index,
                "predicate": predicate,
                "kind": kind,
                "confidence": float(confidence),
            }
        )
    return valid, malformed


def run_secrets_triage(
    project: Project,
    backend: LLMBackend,
    *,
    object_id: str | None = None,
    max_claims: int = 10,
    min_confidence: float = 0.5,
    batch_size: int = 20,
) -> AgentRunResult:
    """Propose secret/suspicious-string claims an LLM notices, rules missed.

    Reads only string artifacts already in the project (``object_id`` narrows
    to one file). Every proposal is written through :meth:`Project.run` with
    ``producer_kind="agent"``, so it lands as ``proposed`` and is subject to
    the same human review gate as any other agent submission - see the module
    docstring.
    """
    candidates, skipped_existing = _candidate_strings(project, object_id)

    considered = 0
    skipped_low_confidence = 0
    skipped_malformed = 0
    proposed_ids: list[str] = []

    model_name = getattr(backend, "model", None)
    method = f"llm:{model_name}" if model_name else "llm:local"

    index = 0
    while index < len(candidates) and len(proposed_ids) < max_claims:
        batch = list(enumerate(candidates[index : index + batch_size]))
        index += batch_size
        considered += len(batch)

        prompt = _build_prompt(batch)
        raw_response = backend.complete(prompt)
        items, malformed = _parse_items(raw_response, len(batch))
        skipped_malformed += malformed

        by_index = {i: artifact for i, artifact in batch}
        for item in items:
            if len(proposed_ids) >= max_claims:
                break
            confidence = max(0.0, min(1.0, item["confidence"]))
            if confidence < min_confidence:
                skipped_low_confidence += 1
                continue
            artifact = by_index[item["index"]]
            claim_id = _submit_claim(project, artifact, item["predicate"], item["kind"], confidence, method)
            proposed_ids.append(claim_id)

    return AgentRunResult(
        proposed_claim_ids=tuple(proposed_ids),
        considered=considered,
        skipped_existing=skipped_existing,
        skipped_low_confidence=skipped_low_confidence,
        skipped_malformed=skipped_malformed,
    )


def _submit_claim(
    project: Project,
    artifact: Any,
    predicate: str,
    kind: str,
    confidence: float,
    method: str,
) -> str:
    text = str(artifact.data.get("text", ""))
    subject_id = artifact.object_id
    with project.run(
        tool=TOOL_NAME,
        tool_version=YUGEN_VERSION,
        adapter="agents.secrets",
        params={"predicate": predicate, "kind": kind},
    ) as rc:
        if predicate == "contains_hardcoded_secret":
            statement = {
                "secret_kind": kind,
                "detector": f"agent:{TOOL_NAME}",
                "redacted_preview": redact(text, limit=CLAIM_PREVIEW_LENGTH),
            }
        else:
            statement = {
                "category": kind,
                "detector": f"agent:{TOOL_NAME}",
                "preview": sanitize_text(text, limit=CLAIM_PREVIEW_LENGTH),
            }
        claim = rc.add_claim(
            predicate,
            statement,
            [EvidenceRef(artifact.artifact_id, "locus")],
            subject_id=subject_id,
            confidence=confidence,
            producer=TOOL_NAME,
            producer_kind="agent",
            method=method,
        )
    return claim.claim_id


__all__ = [
    "AgentRunResult",
    "SECRET_KINDS",
    "SUSPICIOUS_CATEGORIES",
    "TOOL_NAME",
    "run_secrets_triage",
]
