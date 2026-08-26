"""The evidence model's invariants.

Aether's first principle is that an agent cannot emit a free-text security
claim. These tests are that principle, written down as assertions.
"""

from __future__ import annotations

import pytest

from aether.errors import EvidenceError, SchemaError
from aether.evidence.models import (
    Artifact,
    Attestation,
    Claim,
    ClaimLink,
    EvidenceRef,
    combine_confidence,
)
from aether.evidence.schemas import (
    ARTIFACT_KINDS,
    CLAIM_PREDICATES,
    check_evidence_requirements,
    describe_registries,
    validate_artifact_data,
)

FILE_DATA = {
    "path": "bin/target",
    "sha256": "a" * 64,
    "size": 1024,
    "format": "elf",
    "source": "ingest",
}


def make_file() -> Artifact:
    return Artifact.create("file", FILE_DATA)


# -- artifacts --------------------------------------------------------------


def test_identity_fields_alone_determine_the_id():
    obj = make_file()
    lean = Artifact.create(
        "function", {"name": "main", "addr_start": 4096}, object_id=obj.artifact_id
    )
    enriched = Artifact.create(
        "function",
        {
            "name": "main",
            "addr_start": 4096,
            "size": 64,
            "signature": "int main(int, char **)",
            "calling_convention": "__cdecl",
        },
        object_id=obj.artifact_id,
    )
    assert lean.artifact_id == enriched.artifact_id


def test_different_objects_give_different_ids():
    first = make_file()
    second = Artifact.create("file", {**FILE_DATA, "path": "bin/other"})
    left = Artifact.create("function", {"name": "main", "addr_start": 1}, object_id=first.artifact_id)
    right = Artifact.create(
        "function", {"name": "main", "addr_start": 1}, object_id=second.artifact_id
    )
    assert left.artifact_id != right.artifact_id


def test_string_identity_prefers_virtual_address():
    """A string found by offset and by address must be one artifact.

    This is what makes a header parser and a disassembler converge instead of
    each contributing its own copy of the same literal.
    """
    obj = make_file()
    common = {"text": "AKIAIOSFODNN7EXAMPLE", "encoding": "ascii"}
    by_both = Artifact.create(
        "string", {**common, "addr": 0x4001C0, "file_offset": 0x1C0}, object_id=obj.artifact_id
    )
    by_address = Artifact.create(
        "string", {**common, "addr": 0x4001C0}, object_id=obj.artifact_id
    )
    by_offset = Artifact.create(
        "string", {**common, "file_offset": 0x1C0}, object_id=obj.artifact_id
    )
    assert by_both.artifact_id == by_address.artifact_id
    assert by_offset.artifact_id != by_address.artifact_id


def test_import_identity_is_the_symbol_name():
    obj = make_file()
    bare = Artifact.create("import", {"name": "strcpy"}, object_id=obj.artifact_id)
    with_library = Artifact.create(
        "import", {"name": "strcpy", "library": "libc.so.6"}, object_id=obj.artifact_id
    )
    assert bare.artifact_id == with_library.artifact_id


def test_located_artifact_requires_an_object():
    with pytest.raises(SchemaError, match="requires an object_id"):
        Artifact.create("function", {"name": "main", "addr_start": 0})


def test_standalone_artifact_refuses_an_object():
    with pytest.raises(SchemaError, match="standalone"):
        Artifact.create("file", FILE_DATA, object_id="art_" + "0" * 32)


def test_undeclared_artifact_fields_are_rejected():
    with pytest.raises(SchemaError, match="undeclared"):
        validate_artifact_data("function", {"name": "m", "addr_start": 0, "danger": "high"})


def test_enum_and_type_violations_are_rejected():
    with pytest.raises(SchemaError, match="must be one of"):
        validate_artifact_data("file", {**FILE_DATA, "format": "wasm"})
    with pytest.raises(SchemaError, match="must be int"):
        validate_artifact_data("file", {**FILE_DATA, "size": "1024"})


def test_bool_does_not_satisfy_int():
    with pytest.raises(SchemaError, match="got bool"):
        validate_artifact_data("file", {**FILE_DATA, "size": True})


def test_unknown_artifact_kind_names_the_known_ones():
    with pytest.raises(SchemaError, match="known kinds"):
        validate_artifact_data("disassembly", {})


def test_string_with_neither_address_nor_offset_is_rejected():
    with pytest.raises(SchemaError, match="identity group"):
        validate_artifact_data("string", {"text": "hi", "encoding": "ascii"})


# -- claims -----------------------------------------------------------------


def _claim_setup():
    obj = make_file()
    string = Artifact.create(
        "string",
        {"text": "AKIAIOSFODNN7EXAMPLE", "encoding": "ascii", "addr": 0x2000},
        object_id=obj.artifact_id,
    )
    function = Artifact.create(
        "function", {"name": "main", "addr_start": 0x1000}, object_id=obj.artifact_id
    )
    kinds = {
        obj.artifact_id: "file",
        string.artifact_id: "string",
        function.artifact_id: "function",
    }
    return obj, string, function, kinds


def test_a_claim_without_evidence_is_impossible():
    obj, _string, _function, _kinds = _claim_setup()
    with pytest.raises(EvidenceError, match="no evidence"):
        Claim.create("contains_string", {"text": "x"}, [], subject_id=obj.artifact_id)


def test_free_text_in_a_statement_is_rejected():
    """The core principle: prose cannot enter the graph as a finding."""
    _obj, string, _function, kinds = _claim_setup()
    with pytest.raises(SchemaError, match="undeclared"):
        Claim.create(
            "contains_string",
            {"text": "x", "note": "this looks exploitable to me"},
            [EvidenceRef(string.artifact_id)],
            evidence_kinds=kinds,
        )


def test_no_predicate_accepts_a_prose_field():
    """Guards against a future predicate quietly reopening the door."""
    prose_names = {"note", "notes", "description", "comment", "rationale", "summary",
                   "explanation", "details", "finding", "message"}
    for name, predicate in CLAIM_PREDICATES.items():
        offending = {f.name for f in predicate.fields} & prose_names
        assert not offending, f"predicate {name} declares free-text field(s) {offending}"


def test_evidence_of_the_wrong_kind_is_rejected():
    _obj, _string, function, kinds = _claim_setup()
    with pytest.raises(EvidenceError, match="accepts"):
        Claim.create(
            "contains_string",
            {"text": "x"},
            [EvidenceRef(function.artifact_id)],
            evidence_kinds=kinds,
        )


def test_evidence_in_the_wrong_role_does_not_satisfy_a_requirement():
    _obj, string, _function, kinds = _claim_setup()
    with pytest.raises(EvidenceError, match="requires at least"):
        Claim.create(
            "contains_string",
            {"text": "x"},
            [EvidenceRef(string.artifact_id, "context")],
            evidence_kinds=kinds,
        )


def test_unknown_role_is_rejected():
    with pytest.raises(EvidenceError, match="unknown evidence role"):
        EvidenceRef("art_" + "0" * 32, "hunch")


def test_claim_id_ignores_evidence_ordering():
    _obj, string, _function, kinds = _claim_setup()
    extra = Artifact.create(
        "string", {"text": "b", "encoding": "ascii", "addr": 0x3000}, object_id=_obj.artifact_id
    )
    kinds[extra.artifact_id] = "string"
    refs = [EvidenceRef(string.artifact_id), EvidenceRef(extra.artifact_id)]
    first = Claim.create("contains_string", {"text": "x"}, refs, evidence_kinds=kinds)
    second = Claim.create(
        "contains_string", {"text": "x"}, list(reversed(refs)), evidence_kinds=kinds
    )
    assert first.claim_id == second.claim_id


def test_duplicate_evidence_refs_collapse():
    _obj, string, _function, kinds = _claim_setup()
    claim = Claim.create(
        "contains_string",
        {"text": "x"},
        [EvidenceRef(string.artifact_id), EvidenceRef(string.artifact_id)],
        evidence_kinds=kinds,
    )
    assert len(claim.evidence) == 1


def test_claim_id_is_independent_of_producer():
    """Two engines reaching the same conclusion produce one claim, not two."""
    _obj, string, _function, kinds = _claim_setup()
    statement = {"secret_kind": "aws_access_key", "detector": "rule:aws"}
    left = Claim.create(
        "contains_hardcoded_secret",
        statement,
        [EvidenceRef(string.artifact_id)],
        evidence_kinds=kinds,
    )
    right = Claim.create(
        "contains_hardcoded_secret",
        dict(statement),
        [EvidenceRef(string.artifact_id)],
        evidence_kinds=kinds,
    )
    assert left.claim_id == right.claim_id


def test_optional_evidence_requirement_is_optional():
    obj, string, function, kinds = _claim_setup()
    claim = Claim.create(
        "uses_risky_api",
        {"api": "strcpy", "category": "memory_copy"},
        [EvidenceRef(function.artifact_id, "locus")],
        subject_id=obj.artifact_id,
        evidence_kinds=kinds,
    )
    assert claim.statement["api"] == "strcpy"


def test_unknown_predicate_lists_the_known_ones():
    with pytest.raises(SchemaError, match="known predicates"):
        Claim.create("is_definitely_vulnerable", {}, [EvidenceRef("art_" + "0" * 32)])


def test_check_evidence_requirements_rejects_unknown_roles():
    with pytest.raises(EvidenceError, match="unknown evidence role"):
        check_evidence_requirements("contains_string", {"vibes": ["string"]})


# -- links and confidence ---------------------------------------------------


def test_claim_cannot_link_to_itself():
    with pytest.raises(EvidenceError, match="cannot link to itself"):
        ClaimLink("clm_" + "0" * 32, "clm_" + "0" * 32, "supports")


def test_unknown_relation_is_rejected():
    with pytest.raises(EvidenceError, match="unknown claim relation"):
        ClaimLink("clm_" + "0" * 32, "clm_" + "1" * 32, "vaguely_related")


def test_confidence_takes_the_max_within_a_producer():
    combined = combine_confidence(
        [{"producer": "ghidra", "confidence": 0.4}, {"producer": "ghidra", "confidence": 0.8}]
    )
    assert combined["combined"] == 0.8
    assert combined["producers"] == 1


def test_independent_producers_corroborate():
    combined = combine_confidence(
        [{"producer": "ghidra", "confidence": 0.7}, {"producer": "triage", "confidence": 0.7}]
    )
    assert combined["combined"] == pytest.approx(0.91)
    assert combined["producers"] == 2


def test_confidence_never_exceeds_one():
    combined = combine_confidence(
        [{"producer": str(i), "confidence": 0.99} for i in range(10)]
    )
    assert combined["combined"] <= 1.0


def test_no_attestations_means_no_confidence():
    assert combine_confidence([])["combined"] == 0.0


def test_attestation_rejects_out_of_range_confidence():
    with pytest.raises(EvidenceError, match="within"):
        Attestation.create(
            "clm_" + "0" * 32,
            producer_kind="tool",
            producer="x",
            run_id="run_" + "0" * 32,
            confidence=1.5,
            created_at="2026-01-01T00:00:00Z",
        )


def test_attestation_rejects_unknown_producer_kind():
    with pytest.raises(EvidenceError, match="unknown producer kind"):
        Attestation.create(
            "clm_" + "0" * 32,
            producer_kind="oracle",
            producer="x",
            run_id="run_" + "0" * 32,
            confidence=0.5,
            created_at="2026-01-01T00:00:00Z",
        )


# -- registry ---------------------------------------------------------------


def test_registries_are_fully_describable():
    described = describe_registries()
    assert set(described["artifact_kinds"]) == set(ARTIFACT_KINDS)
    assert set(described["claim_predicates"]) == set(CLAIM_PREDICATES)
    for spec in described["claim_predicates"].values():
        assert spec["schema_id"].startswith("aether.claim.")


def test_every_predicate_requires_at_least_one_artifact():
    """No predicate may be assertable without evidence."""
    for name, predicate in CLAIM_PREDICATES.items():
        mandatory = [r for r in predicate.requires_evidence if r.minimum > 0]
        assert mandatory, f"predicate {name} can be asserted with no required evidence"
