"""Project store: persistence, provenance, and the invariants at rest."""

from __future__ import annotations

import sqlite3

import pytest

from aether.errors import EvidenceError, ProjectError
from aether.evidence.models import EvidenceRef
from aether.project import Project

FILE_DATA = {
    "path": "bin/target",
    "sha256": "b" * 64,
    "size": 512,
    "format": "elf",
    "source": "ingest",
}


def seed(project: Project, *, producer: str = "engine-a", confidence: float = 0.9):
    """Write one file, one string, and one claim about the string."""
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_DATA)
        string = rc.artifact(
            "string",
            {"text": "AKIAIOSFODNN7EXAMPLE", "encoding": "ascii", "addr": 0x2000},
            object_id=obj.artifact_id,
        )
        claim = rc.add_claim(
            "contains_hardcoded_secret",
            {"secret_kind": "aws_access_key", "detector": "rule:aws"},
            [EvidenceRef(string.artifact_id, "locus")],
            subject_id=obj.artifact_id,
            confidence=confidence,
            producer=producer,
        )
    return obj, string, claim


# -- lifecycle --------------------------------------------------------------


def test_create_open_and_discover(tmp_path):
    root = tmp_path / "nested" / "proj"
    project = Project.create(str(root), "demo")
    assert project.info()["name"] == "demo"
    project.close()

    reopened = Project.open(str(root))
    assert reopened.info()["project_id"] is not None
    reopened.close()

    deep = root / "a" / "b"
    deep.mkdir(parents=True)
    assert Project.discover(str(deep)) == str(root)


def test_creating_over_an_existing_project_is_refused(tmp_path):
    root = str(tmp_path / "proj")
    Project.create(root, "one").close()
    with pytest.raises(ProjectError, match="already exists"):
        Project.create(root, "two")
    Project.create(root, "two", exist_ok=True).close()


def test_opening_a_missing_project_explains_the_fix(tmp_path):
    with pytest.raises(ProjectError, match="aether init"):
        Project.open(str(tmp_path / "nothing"))


def test_read_only_projects_refuse_runs(tmp_path):
    root = str(tmp_path / "proj")
    Project.create(root, "ro").close()
    project = Project.open(root, read_only=True)
    with pytest.raises(ProjectError, match="read-only"):
        with project.run(tool="t", tool_version="1", adapter="test"):
            pass
    project.close()


# -- runs and provenance ----------------------------------------------------


def test_a_failed_run_writes_nothing_but_is_still_recorded(project):
    seed(project)
    before = project.stats()["totals"]["artifacts"]

    with pytest.raises(RuntimeError):
        with project.run(tool="bad", tool_version="1", adapter="test") as rc:
            rc.artifact("file", {**FILE_DATA, "path": "bin/other", "sha256": "c" * 64})
            raise RuntimeError("engine crashed")

    assert project.stats()["totals"]["artifacts"] == before
    assert "failed" in {run["status"] for run in project.runs()}


def test_every_artifact_carries_provenance(project):
    seed(project)
    assert not [p for p in project.check() if p["kind"] == "artifact_without_provenance"]


def test_run_records_parameters_and_versions(project):
    with project.run(
        tool="ghidra", tool_version="11.1.2", adapter="ghidra", params={"decompile_limit": 5}
    ) as rc:
        rc.artifact("file", FILE_DATA)
    run = project.runs()[0]
    assert run["tool_version"] == "11.1.2"
    assert run["params"] == {"decompile_limit": 5}
    assert run["status"] == "ok"


# -- convergence ------------------------------------------------------------


def test_a_second_observation_converges_and_enriches(project):
    obj, string, _claim = seed(project)
    with project.run(tool="t2", tool_version="1", adapter="test") as rc:
        again = rc.artifact(
            "string",
            {
                "text": "AKIAIOSFODNN7EXAMPLE",
                "encoding": "ascii",
                "addr": 0x2000,
                "section": ".rodata",
            },
            object_id=obj.artifact_id,
        )
        assert again.artifact_id == string.artifact_id
        assert rc.artifacts_new == 0

    stored = project.get_artifact(string.artifact_id)
    assert stored.data["section"] == ".rodata"
    assert project.count_artifacts(kind="string") == 1


def test_conflicting_non_identity_fields_are_reported_not_overwritten(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_DATA)
        rc.artifact(
            "function",
            {"name": "main", "addr_start": 0x1000, "addr_end": 0x1050},
            object_id=obj.artifact_id,
        )

    with project.run(tool="t2", tool_version="1", adapter="test") as rc:
        rc.artifact(
            "function",
            {"name": "main", "addr_start": 0x1000, "addr_end": 0x1099},
            object_id=obj.artifact_id,
        )
        conflicts = rc.field_conflicts

    assert conflicts and conflicts[0]["field"] == "addr_end"
    assert conflicts[0]["kept"] == 0x1050
    assert conflicts[0]["rejected"] == 0x1099


def test_two_producers_attest_to_one_claim(project):
    _obj, _string, claim = seed(project, producer="engine-a", confidence=0.7)
    seed(project, producer="engine-b", confidence=0.7)

    stored = project.get_claim(claim.claim_id)
    assert project.stats()["totals"]["claims"] == 1
    assert stored["confidence"]["producers"] == 2
    assert stored["confidence"]["combined"] == pytest.approx(0.91)
    assert len(stored["attestations"]) == 2


# -- claim invariants at rest ------------------------------------------------


def test_claims_citing_absent_artifacts_are_refused(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_DATA)
        with pytest.raises(EvidenceError, match="not present in the project"):
            rc.add_claim(
                "contains_string",
                {"text": "x"},
                [EvidenceRef("art_" + "0" * 32)],
                subject_id=obj.artifact_id,
                confidence=0.5,
                producer="test",
            )


def test_deleting_the_last_evidence_row_is_refused_by_the_database(project):
    _obj, _string, claim = seed(project)
    with pytest.raises(sqlite3.IntegrityError, match="strand a claim"):
        project._conn.execute(
            "DELETE FROM claim_evidence WHERE claim_id = ?", (claim.claim_id,)
        )


def test_an_artifact_cited_as_evidence_cannot_be_deleted(project):
    _obj, string, _claim = seed(project)
    with pytest.raises(sqlite3.IntegrityError):
        project._conn.execute(
            "DELETE FROM artifacts WHERE artifact_id = ?", (string.artifact_id,)
        )


def test_integrity_check_is_clean_on_a_healthy_project(project):
    seed(project)
    assert project.check() == []


def test_integrity_check_notices_a_hand_edited_orphan(project):
    """Simulates a hand-edited database, which is the realistic failure mode."""
    _obj, _string, claim = seed(project)
    project._conn.execute("PRAGMA foreign_keys = OFF")
    project._conn.execute("DROP TRIGGER trg_claim_evidence_min")
    project._conn.execute("DELETE FROM claim_evidence WHERE claim_id = ?", (claim.claim_id,))
    problems = project.check()
    assert any(p["kind"] == "claim_without_evidence" for p in problems)


def test_claim_links_require_known_claims(project):
    _obj, _string, claim = seed(project)
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        with pytest.raises(EvidenceError, match="unknown claim"):
            rc.link_claims(claim.claim_id, "clm_" + "0" * 32, "supports")


def test_contradictions_are_reported(project):
    obj, string, first = seed(project)
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        second = rc.add_claim(
            "binary_hardening",
            {"feature": "nx", "present": False},
            [EvidenceRef(obj.artifact_id, "locus")],
            subject_id=obj.artifact_id,
            confidence=0.6,
            producer="engine-b",
        )
        rc.link_claims(second.claim_id, first.claim_id, "contradicts")

    pairs = project.contradictions()
    assert len(pairs) == 1
    assert pairs[0]["left"]["predicate"] == "binary_hardening"


# -- queries ----------------------------------------------------------------


def test_address_lookup_finds_the_containing_range(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_DATA)
        rc.artifact(
            "function",
            {"name": "main", "addr_start": 0x1000, "addr_end": 0x1100},
            object_id=obj.artifact_id,
        )
    found = project.find_artifacts(addr=0x1080)
    assert [a.name for a in found] == ["main"]
    assert project.find_artifacts(addr=0x2000) == []


def test_object_resolution_accepts_a_path_suffix(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        rc.artifact("file", {**FILE_DATA, "path": "squashfs-root/bin/busybox"})
    assert project.resolve_object("busybox").data["path"].endswith("busybox")
    assert project.resolve_object("nonexistent") is None


def test_id_prefixes_resolve_like_git_hashes(project):
    _obj, _string, claim = seed(project)
    assert project.get_claim(claim.claim_id[:16])["id"] == claim.claim_id
    assert project.get_artifact(_string.artifact_id[:16]).artifact_id == _string.artifact_id


def test_name_search_treats_underscores_literally(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_DATA)
        rc.artifact("import", {"name": "a_b"}, object_id=obj.artifact_id)
        rc.artifact("import", {"name": "axb"}, object_id=obj.artifact_id)
    found = project.find_artifacts(kind="import", name_contains="a_b")
    assert [a.name for a in found] == ["a_b"]


def test_confidence_filter_applies_after_aggregation(project):
    seed(project, producer="engine-a", confidence=0.7)
    seed(project, producer="engine-b", confidence=0.7)
    assert project.find_claims(min_confidence=0.9)
    assert not project.find_claims(min_confidence=0.95)


def test_limits_are_clamped(project):
    seed(project)
    assert len(project.find_artifacts(limit=10**9)) <= 5000
    assert project.find_artifacts(limit="not a number") is not None


def test_status_promotion(project):
    _obj, _string, claim = seed(project)
    project.set_claim_status(claim.claim_id, "accepted")
    assert project.get_claim(claim.claim_id)["status"] == "accepted"
    with pytest.raises(EvidenceError, match="unknown claim status"):
        project.set_claim_status(claim.claim_id, "probably_fine")


def test_neighbors_walks_claims_and_evidence(project):
    _obj, string, claim = seed(project)
    graph = project.neighbors(claim.claim_id, depth=2)
    assert string.artifact_id in graph["nodes"]
    assert any(e["relation"].startswith("evidence:") for e in graph["edges"])


def test_annotations_are_stored_apart_from_claims(project):
    obj, _string, _claim = seed(project)
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        rc.annotate("artifact", obj.artifact_id, "reviewed by hand, looks fine")
    notes = project.annotations(obj.artifact_id)
    assert len(notes) == 1
    assert project.stats()["totals"]["claims"] == 1
