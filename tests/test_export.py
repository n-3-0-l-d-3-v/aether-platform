"""Deterministic export.

The claim being defended: re-running the same analysis over the same bytes
produces a byte-identical ``graph/`` tree, so a Git diff shows discoveries
rather than noise.
"""

from __future__ import annotations

import json
import os

from aether.adapters.ghidra import GhidraAdapter
from aether.adapters.triage import TriageAdapter
from aether.export import GRAPH_STREAMS, export_project, graph_digest
from aether.project import Project


def _analyzed(root: str, elf_sample: str) -> Project:
    project = Project.create(root, "export-test")
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    return project


def test_two_independent_analyses_export_identical_graphs(tmp_path, elf_sample):
    first = _analyzed(str(tmp_path / "p1"), elf_sample)
    left = export_project(first, str(tmp_path / "e1"))
    first.close()

    second = _analyzed(str(tmp_path / "p2"), elf_sample)
    right = export_project(second, str(tmp_path / "e2"))
    second.close()

    assert left["graph_digest"] == right["graph_digest"]
    for stream in GRAPH_STREAMS:
        name = f"graph/{stream}.jsonl"
        assert left["files"][name]["digest"] == right["files"][name]["digest"]


def test_the_ledger_differs_even_when_the_graph_does_not(tmp_path, elf_sample):
    """Provenance is a record of events; it is supposed to change."""
    first = _analyzed(str(tmp_path / "p1"), elf_sample)
    left = export_project(first, str(tmp_path / "e1"))
    first.close()

    second = _analyzed(str(tmp_path / "p2"), elf_sample)
    right = export_project(second, str(tmp_path / "e2"))
    second.close()

    assert left["files"]["ledger/runs.jsonl"]["digest"] != (
        right["files"]["ledger/runs.jsonl"]["digest"]
    )


def test_re_analysis_leaves_the_graph_unchanged(tmp_path, elf_sample):
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    before = export_project(project, str(tmp_path / "e1"))["graph_digest"]
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    after = export_project(project, str(tmp_path / "e2"))["graph_digest"]
    project.close()
    assert before == after


def test_new_evidence_does_change_the_graph(tmp_path, elf_sample, ghidra_export_dir):
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    before = export_project(project, str(tmp_path / "e1"))["graph_digest"]
    objects = project.objects()
    GhidraAdapter().import_directory(
        project, ghidra_export_dir, object_id=objects[0].artifact_id
    )
    after = export_project(project, str(tmp_path / "e2"))["graph_digest"]
    project.close()
    assert before != after


def test_export_layout_and_manifest(tmp_path, elf_sample):
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    out = str(tmp_path / "e")
    manifest = export_project(project, out)
    project.close()

    for stream in GRAPH_STREAMS:
        assert os.path.isfile(os.path.join(out, "graph", f"{stream}.jsonl"))
    for stream in ("runs", "attestations", "observations"):
        assert os.path.isfile(os.path.join(out, "ledger", f"{stream}.jsonl"))
    assert os.path.isfile(os.path.join(out, "project.json"))
    assert graph_digest(out) == manifest["graph_digest"]


def test_stable_only_omits_the_ledger(tmp_path, elf_sample):
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    out = str(tmp_path / "e")
    manifest = export_project(project, out, stable_only=True)
    project.close()

    assert not os.path.isdir(os.path.join(out, "ledger"))
    assert all(name.startswith("graph/") for name in manifest["files"])


def test_graph_records_carry_no_provenance(tmp_path, elf_sample):
    """A timestamp in graph/ would defeat the whole point of the split."""
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    out = str(tmp_path / "e")
    export_project(project, out)
    project.close()

    forbidden = {"run_id", "created_at", "observed_at", "producer", "confidence"}
    for stream in GRAPH_STREAMS:
        path = os.path.join(out, "graph", f"{stream}.jsonl")
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    assert not (forbidden & set(json.loads(line)))


def test_exported_lines_are_canonical_and_sorted(tmp_path, elf_sample):
    project = _analyzed(str(tmp_path / "p"), elf_sample)
    out = str(tmp_path / "e")
    export_project(project, out)
    project.close()

    path = os.path.join(out, "graph", "artifacts.jsonl")
    with open(path, encoding="utf-8") as handle:
        ids = []
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            ids.append(record["id"])
            assert line.strip() == json.dumps(
                record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
    assert ids == sorted(ids)


def test_export_can_be_taken_from_a_read_only_project(tmp_path, elf_sample):
    root = str(tmp_path / "p")
    project = _analyzed(root, elf_sample)
    project.close()

    reopened = Project.open(root, read_only=True)
    manifest = export_project(reopened, str(tmp_path / "e"))
    reopened.close()
    assert manifest["files"]["graph/claims.jsonl"]["records"] > 0
