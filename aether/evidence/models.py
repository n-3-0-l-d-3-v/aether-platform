"""Record types for the evidence graph.

The split between :class:`Claim` and :class:`Attestation` is the one modelling
decision here worth reading twice.

A *claim* is an assertion about evidence: predicate, subject, structured
statement, and the artifacts backing it. It carries no producer and no
timestamp, so it is content-addressed and stable - the same assertion made by
Ghidra on Monday and by an agent on Friday is *one* claim.

An *attestation* is one producer standing behind that claim at one moment,
with a confidence. Two independent producers attesting to the same claim is the
signal an evidence-first system exists to capture; folding provenance into the
claim id would have thrown it away and left two near-duplicate rows instead.

Consequence: confidence is never a property of a claim. It is derived from the
attestations, by :func:`combine_confidence`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from aether.canonical import canonical_json, mint_id
from aether.errors import EvidenceError, SchemaError
from aether.evidence.schemas import (
    EVIDENCE_ROLES,
    artifact_kind,
    check_evidence_requirements,
    claim_predicate,
    validate_artifact_data,
    validate_claim_statement,
)

#: Relations between claims. ``supports`` / ``contradicts`` are the two that
#: drive contradiction reporting; the rest are bookkeeping.
CLAIM_RELATIONS: tuple[str, ...] = (
    "supports",
    "contradicts",
    "refines",
    "supersedes",
    "duplicates",
)

#: Curation states. Adapters emit ``proposed``; a human or a gate promotes.
CLAIM_STATUSES: tuple[str, ...] = ("proposed", "accepted", "rejected", "superseded")

PRODUCER_KINDS: tuple[str, ...] = ("tool", "agent", "human", "import")


# --------------------------------------------------------------------------
# Artifacts
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Artifact:
    """A concrete, locatable piece of evidence."""

    artifact_id: str
    kind: str
    data: dict[str, Any]
    #: The file artifact this observation lives inside. ``None`` only for
    #: standalone kinds (currently just ``file``).
    object_id: str | None = None
    #: Containment: the image or archive a carved file came out of.
    parent_id: str | None = None

    @staticmethod
    def create(
        kind: str,
        data: Mapping[str, Any],
        *,
        object_id: str | None = None,
        parent_id: str | None = None,
    ) -> "Artifact":
        """Validate ``data`` and mint a content-addressed artifact.

        The id is a function of the kind, the owning object, and only those
        fields the schema marks as identity fields. Enriching an artifact later
        (adding a size, a section name) therefore does not change its id.
        """
        spec = artifact_kind(kind)
        validated = validate_artifact_data(kind, data)

        if spec.standalone:
            if object_id is not None:
                raise SchemaError(
                    f"artifact kind {kind!r} is standalone and takes no object_id"
                )
        elif object_id is None:
            raise SchemaError(
                f"artifact kind {kind!r} describes a location and requires an "
                "object_id naming the file it was observed in"
            )

        identity = spec.identity_of(validated)
        artifact_id = mint_id(
            "art", {"kind": kind, "object": object_id, "identity": identity}
        )
        return Artifact(
            artifact_id=artifact_id,
            kind=kind,
            data=validated,
            object_id=object_id,
            parent_id=parent_id,
        )

    @property
    def addr_start(self) -> int | None:
        """Primary address, normalized across kinds for indexed lookup."""
        for key in ("addr_start", "addr", "from_addr", "function_addr", "file_offset"):
            value = self.data.get(key)
            if isinstance(value, int):
                return value
        return None

    @property
    def addr_end(self) -> int | None:
        value = self.data.get("addr_end")
        return value if isinstance(value, int) else None

    @property
    def name(self) -> str | None:
        """Human-facing label, normalized across kinds."""
        for key in ("name", "path", "function_name", "signature", "text", "label"):
            value = self.data.get(key)
            if isinstance(value, str):
                return value
        return None

    def to_record(self) -> dict[str, Any]:
        """Deterministic export form. Deliberately free of provenance."""
        record: dict[str, Any] = {
            "id": self.artifact_id,
            "kind": self.kind,
            "data": self.data,
        }
        if self.object_id is not None:
            record["object_id"] = self.object_id
        if self.parent_id is not None:
            record["parent_id"] = self.parent_id
        return record


# --------------------------------------------------------------------------
# Claims
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRef:
    """One artifact attached to a claim, in a role."""

    artifact_id: str
    role: str = "locus"

    def __post_init__(self) -> None:
        if self.role not in EVIDENCE_ROLES:
            raise EvidenceError(
                f"unknown evidence role {self.role!r}; expected one of "
                f"{list(EVIDENCE_ROLES)}"
            )

    def as_tuple(self) -> tuple[str, str]:
        return (self.role, self.artifact_id)


@dataclass(frozen=True)
class Claim:
    """A structured assertion backed by evidence.

    There is no free-text field, by construction: ``statement`` is validated
    against a registered predicate that declares every permissible key.
    """

    claim_id: str
    predicate: str
    schema_id: str
    statement: dict[str, Any]
    evidence: tuple[EvidenceRef, ...]
    subject_id: str | None = None
    status: str = "proposed"

    @staticmethod
    def create(
        predicate: str,
        statement: Mapping[str, Any],
        evidence: Sequence[EvidenceRef],
        *,
        subject_id: str | None = None,
        status: str = "proposed",
        evidence_kinds: Mapping[str, str] | None = None,
    ) -> "Claim":
        """Validate and mint a claim.

        ``evidence_kinds`` maps artifact id to artifact kind. The store passes
        it in so :func:`check_evidence_requirements` can verify that, say, a
        ``contains_string`` claim points at an actual string artifact rather
        than at whatever happened to be nearby. It is optional here only so the
        dataclass stays usable in tests; the store always supplies it.
        """
        spec = claim_predicate(predicate)
        validated = validate_claim_statement(predicate, statement)

        if status not in CLAIM_STATUSES:
            raise EvidenceError(
                f"unknown claim status {status!r}; expected one of {list(CLAIM_STATUSES)}"
            )
        if not evidence:
            raise EvidenceError(
                f"claim[{predicate}] was submitted with no evidence. Every claim "
                "must link at least one artifact; this is not overridable."
            )

        seen: set[tuple[str, str]] = set()
        deduped: list[EvidenceRef] = []
        for ref in evidence:
            key = ref.as_tuple()
            if key not in seen:
                seen.add(key)
                deduped.append(ref)
        deduped.sort(key=lambda r: r.as_tuple())

        if evidence_kinds is not None:
            roles: dict[str, list[str]] = {}
            for ref in deduped:
                kind = evidence_kinds.get(ref.artifact_id)
                if kind is None:
                    raise EvidenceError(
                        f"claim[{predicate}] references unknown artifact "
                        f"{ref.artifact_id}"
                    )
                roles.setdefault(ref.role, []).append(kind)
            check_evidence_requirements(predicate, roles)

        claim_id = mint_id(
            "clm",
            {
                "schema": spec.schema_id,
                "subject": subject_id,
                "statement": validated,
                "evidence": [list(r.as_tuple()) for r in deduped],
            },
        )
        return Claim(
            claim_id=claim_id,
            predicate=predicate,
            schema_id=spec.schema_id,
            statement=validated,
            evidence=tuple(deduped),
            subject_id=subject_id,
            status=status,
        )

    def to_record(self) -> dict[str, Any]:
        """Deterministic export form. Provenance lives in the ledger."""
        record: dict[str, Any] = {
            "id": self.claim_id,
            "schema": self.schema_id,
            "predicate": self.predicate,
            "statement": self.statement,
            "evidence": [
                {"role": r.role, "artifact_id": r.artifact_id} for r in self.evidence
            ],
            "status": self.status,
        }
        if self.subject_id is not None:
            record["subject_id"] = self.subject_id
        return record


@dataclass(frozen=True)
class ClaimLink:
    """A typed edge between two claims."""

    src_claim_id: str
    dst_claim_id: str
    relation: str

    def __post_init__(self) -> None:
        if self.relation not in CLAIM_RELATIONS:
            raise EvidenceError(
                f"unknown claim relation {self.relation!r}; expected one of "
                f"{list(CLAIM_RELATIONS)}"
            )
        if self.src_claim_id == self.dst_claim_id:
            raise EvidenceError("a claim cannot link to itself")

    def to_record(self) -> dict[str, Any]:
        return {
            "src": self.src_claim_id,
            "dst": self.dst_claim_id,
            "relation": self.relation,
        }


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    """One execution of an adapter: the unit of provenance."""

    run_id: str
    tool: str
    tool_version: str
    adapter: str
    params: dict[str, Any]
    input_digest: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"
    exit_code: int | None = None
    aether_version: str = ""
    notes: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "id": self.run_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "adapter": self.adapter,
            "params": self.params,
            "input_digest": self.input_digest,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "exit_code": self.exit_code,
            "aether_version": self.aether_version,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Attestation:
    """One producer standing behind one claim, with a confidence."""

    attestation_id: str
    claim_id: str
    producer_kind: str
    producer: str
    run_id: str
    confidence: float
    created_at: str
    method: str = ""

    @staticmethod
    def create(
        claim_id: str,
        *,
        producer_kind: str,
        producer: str,
        run_id: str,
        confidence: float,
        created_at: str,
        method: str = "",
    ) -> "Attestation":
        if producer_kind not in PRODUCER_KINDS:
            raise EvidenceError(
                f"unknown producer kind {producer_kind!r}; expected one of "
                f"{list(PRODUCER_KINDS)}"
            )
        if not 0.0 <= float(confidence) <= 1.0:
            raise EvidenceError(
                f"confidence must be within [0.0, 1.0], got {confidence!r}"
            )
        attestation_id = mint_id(
            "att",
            {
                "claim": claim_id,
                "producer": producer,
                "run": run_id,
                "method": method,
            },
        )
        return Attestation(
            attestation_id=attestation_id,
            claim_id=claim_id,
            producer_kind=producer_kind,
            producer=producer,
            run_id=run_id,
            confidence=round(float(confidence), 6),
            created_at=created_at,
            method=method,
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "id": self.attestation_id,
            "claim_id": self.claim_id,
            "producer_kind": self.producer_kind,
            "producer": self.producer,
            "run_id": self.run_id,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "method": self.method,
        }


def combine_confidence(attestations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate attestation confidences into one reported figure.

    Within a producer we take the maximum: a tool firing two rules is one
    opinion, not two. Across *distinct* producers we combine with noisy-OR,
    which is the right shape for independent corroboration - two 0.7s become
    0.91, not 1.4.

    Independence across producers is an assumption, not a fact. Two adapters
    wrapping the same underlying engine are not independent, and the combined
    figure will flatter them. ``per_producer`` is returned so a caller that
    knows better can recompute.
    """
    best: dict[str, float] = {}
    for att in attestations:
        producer = str(att["producer"])
        confidence = float(att["confidence"])
        if confidence > best.get(producer, -1.0):
            best[producer] = confidence

    if not best:
        return {
            "combined": 0.0,
            "max": 0.0,
            "producers": 0,
            "per_producer": {},
        }

    residual = 1.0
    for confidence in best.values():
        residual *= 1.0 - confidence
    return {
        "combined": round(1.0 - residual, 6),
        "max": round(max(best.values()), 6),
        "producers": len(best),
        "per_producer": {k: round(v, 6) for k, v in sorted(best.items())},
    }


def record_digest(record: Mapping[str, Any]) -> str:
    """Digest of an export record, used by the export manifest."""
    from aether.canonical import content_digest

    return content_digest(record)


__all__ = [
    "Artifact",
    "Attestation",
    "CLAIM_RELATIONS",
    "CLAIM_STATUSES",
    "Claim",
    "ClaimLink",
    "EvidenceRef",
    "PRODUCER_KINDS",
    "Run",
    "canonical_json",
    "combine_confidence",
    "record_digest",
]
