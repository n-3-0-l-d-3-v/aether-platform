"""General evidence-graph diff.

Because artifact and claim ids are content-addressed, diffing two graphs is a
set difference over ids, not a heuristic structural comparison. These tests
defend that: identical analyses must diff to nothing, a real change must be
detected and grouped correctly, and the two snapshot sources (a live project,
an exported directory) must agree with each other.
"""

from __future__ import annotations

import pytest

from aether.errors import AetherError
from aether.evidence.models import EvidenceRef
from aether.export import export_project
from aether.export.diff import (
    DiffError,
    diff_paths,
    diff_snapshots,
    load_snapshot,
    snapshot_from_export,
    snapshot_from_project,
)
from aether.project import Project


def _seed(project: Project, sha256: str, extra_string: str | None = None) -> None:
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact(
            "file", {"path": "bin/app", "sha256": sha256, "size": 1, "format": "elf", "source": "ingest"}
        )
        s = rc.artifact(
            "string", {"text": "hello world", "encoding": "ascii", "addr": 0x1000}, object_id=obj.artifact_id
        )
        rc.add_claim(
            "contains_string",
            {"text": "hello world"},
            [EvidenceRef(s.artifact_id, "locus")],
            subject_id=obj.artifact_id,
            confidence=0.9,
            producer="t",
        )
        if extra_string:
            rc.artifact(
                "string", {"text": extra_string, "encoding": "ascii", "addr": 0x2000}, object_id=obj.artifact_id
            )


# -- snapshots ----------------------------------------------------------


def test_identical_projects_diff_to_nothing(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64)
    _seed(b, "a" * 64)

    diff = diff_snapshots(snapshot_from_project(a, label="a"), snapshot_from_project(b, label="b"))
    assert diff.identical
    assert diff.to_record()["summary"] == {
        "artifacts_added": 0,
        "artifacts_removed": 0,
        "claims_added": 0,
        "claims_removed": 0,
    }
    a.close()
    b.close()


def test_a_new_artifact_and_no_new_claim_is_reported_correctly(tmp_path):
    """Adding a plain string (no detector fires) changes artifacts, not claims."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64)
    _seed(b, "a" * 64, extra_string="a second unrelated string")

    diff = diff_snapshots(snapshot_from_project(a, label="a"), snapshot_from_project(b, label="b"))
    assert not diff.identical
    assert diff.added_artifacts.get("string") and len(diff.added_artifacts["string"]) == 1
    assert not diff.added_claims
    assert not diff.removed_artifacts and not diff.removed_claims
    a.close()
    b.close()


def test_diff_is_directional(tmp_path):
    """Swapping baseline and target swaps added and removed."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64)
    _seed(b, "a" * 64, extra_string="only in b")

    forward = diff_snapshots(snapshot_from_project(a, label="a"), snapshot_from_project(b, label="b"))
    backward = diff_snapshots(snapshot_from_project(b, label="b"), snapshot_from_project(a, label="a"))
    assert forward.added_artifacts and not forward.removed_artifacts
    assert backward.removed_artifacts and not backward.added_artifacts
    assert forward.added_artifacts["string"][0]["id"] == backward.removed_artifacts["string"][0]["id"]
    a.close()
    b.close()


def test_project_and_its_own_export_agree(tmp_path):
    """A live project and its just-exported graph must be indistinguishable."""
    project = Project.create(str(tmp_path / "proj"), "p")
    _seed(project, "b" * 64, extra_string="exported too")
    export_project(project, str(tmp_path / "export"))

    live = snapshot_from_project(project, label="live")
    exported = snapshot_from_export(str(tmp_path / "export"), label="exported")
    diff = diff_snapshots(live, exported)
    assert diff.identical, diff.to_record()
    project.close()


def test_load_snapshot_detects_project_vs_export_automatically(tmp_path):
    project = Project.create(str(tmp_path / "proj"), "p")
    _seed(project, "c" * 64)
    export_project(project, str(tmp_path / "export"))
    project.close()

    from_project = load_snapshot(str(tmp_path / "proj"))
    from_export = load_snapshot(str(tmp_path / "export"))
    assert diff_snapshots(from_project, from_export).identical


def test_diff_paths_is_a_convenience_wrapper(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64)
    _seed(b, "a" * 64)
    a.close()
    b.close()
    assert diff_paths(str(tmp_path / "a"), str(tmp_path / "b")).identical


def test_an_unrecognisable_path_is_a_clean_error(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    with pytest.raises(DiffError, match="neither an Aether project"):
        load_snapshot(str(empty))


def test_an_export_directory_missing_the_graph_stream_is_a_clean_error(tmp_path):
    fake_export = tmp_path / "export"
    fake_export.mkdir()
    with pytest.raises(DiffError, match="does not look like an Aether export"):
        snapshot_from_export(str(fake_export))


def test_removed_and_added_are_both_reported_when_content_diverges(tmp_path):
    """Two genuinely different builds: some ids only in one side, some in the other."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64, extra_string="only in a")
    _seed(b, "a" * 64, extra_string="only in b")

    diff = diff_snapshots(snapshot_from_project(a, label="a"), snapshot_from_project(b, label="b"))
    assert diff.added_artifacts["string"]
    assert diff.removed_artifacts["string"]
    assert diff.added_artifacts["string"][0]["id"] != diff.removed_artifacts["string"][0]["id"]
    a.close()
    b.close()


def test_claim_diff_carries_the_subject_path(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _seed(a, "a" * 64)
    _seed(b, "b" * 64)  # different file digest -> different subject, different claim id

    diff = diff_snapshots(snapshot_from_project(a, label="a"), snapshot_from_project(b, label="b"))
    added = diff.added_claims.get("contains_string", [])
    assert added and added[0]["subject_path"] == "bin/app"
    a.close()
    b.close()


# -- CLI ------------------------------------------------------------------


def test_cli_diff_graph_reports_identical(tmp_path, capsys):
    from aether.cli import main

    main(["init", str(tmp_path / "a")])
    main(["init", str(tmp_path / "b")])
    capsys.readouterr()
    for path in (tmp_path / "a", tmp_path / "b"):
        p = Project.open(str(path))
        _seed(p, "a" * 64)
        p.close()

    assert main(["diff-graph", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    assert "identical" in capsys.readouterr().out


def test_cli_diff_graph_reports_a_real_difference(tmp_path, capsys):
    from aether.cli import main

    main(["init", str(tmp_path / "a")])
    main(["init", str(tmp_path / "b")])
    capsys.readouterr()
    a = Project.open(str(tmp_path / "a"))
    _seed(a, "a" * 64)
    a.close()
    b = Project.open(str(tmp_path / "b"))
    _seed(b, "a" * 64, extra_string="a new string in b")
    b.close()

    assert main(["diff-graph", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    output = capsys.readouterr().out
    assert "added artifacts" in output
    assert "string" in output


def test_cli_diff_graph_can_compare_a_project_to_an_export(tmp_path, capsys):
    from aether.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()
    project = Project.open(root)
    _seed(project, "a" * 64)
    project.close()

    assert main(["-P", root, "export", str(tmp_path / "export")]) == 0
    capsys.readouterr()

    assert main(["diff-graph", root, str(tmp_path / "export")]) == 0
    assert "identical" in capsys.readouterr().out


def test_cli_diff_graph_on_a_bad_path_is_a_clean_error(tmp_path, capsys):
    from aether.cli import main

    (tmp_path / "junk").mkdir()
    assert main(["diff-graph", str(tmp_path / "junk"), str(tmp_path / "junk")]) != 0
    assert "neither an Aether project" in capsys.readouterr().err
