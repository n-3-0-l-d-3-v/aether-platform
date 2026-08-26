"""The CLI surface and the evaluation harness.

The evaluation tests are the Phase 0 success gate in executable form: analyze
real binaries, check the claims against ground truth, and fail loudly if either
recall or the evidence links regress.
"""

from __future__ import annotations

import json
import os

import pytest

from aether.cli import main
from aether.eval import EvalError, load_suite, run_suite, run_suites

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SUITES = os.path.join(REPO_ROOT, "eval", "suites")


# -- CLI --------------------------------------------------------------------


def run_cli(*argv: str) -> int:
    return main(list(argv))


def test_init_creates_a_project(tmp_path, capsys):
    root = str(tmp_path / "proj")
    assert run_cli("init", root, "--name", "demo") == 0
    assert os.path.isfile(os.path.join(root, "aether.db"))
    assert "initialized project 'demo'" in capsys.readouterr().out


def test_analyze_query_and_export_round_trip(tmp_path, elf_sample, capsys):
    root = str(tmp_path / "proj")
    assert run_cli("init", root) == 0
    assert run_cli("-P", root, "analyze", elf_sample, "--path", "bin/agent") == 0
    capsys.readouterr()

    assert run_cli("-P", root, "--json", "query", "objects") == 0
    objects = json.loads(capsys.readouterr().out)
    assert objects[0]["path"] == "bin/agent"

    assert run_cli(
        "-P", root, "--json", "query", "claims", "--predicate", "contains_hardcoded_secret"
    ) == 0
    claims = json.loads(capsys.readouterr().out)
    assert claims and claims[0]["evidence_count"] >= 1

    out = str(tmp_path / "export")
    assert run_cli("-P", root, "export", out) == 0
    capsys.readouterr()
    assert os.path.isfile(os.path.join(out, "graph", "claims.jsonl"))

    assert run_cli("-P", root, "check") == 0
    assert "intact" in capsys.readouterr().out


def test_query_claim_accepts_a_short_id(tmp_path, elf_sample, capsys):
    root = str(tmp_path / "proj")
    run_cli("init", root)
    run_cli("-P", root, "analyze", elf_sample)
    capsys.readouterr()

    run_cli("-P", root, "--json", "query", "claims", "--limit", "1")
    claim_id = json.loads(capsys.readouterr().out)[0]["claim_id"]

    assert run_cli("-P", root, "query", "claim", claim_id[:16]) == 0
    output = capsys.readouterr().out
    assert "evidence" in output
    assert "attestations" in output


def test_firmware_analysis_via_the_cli(tmp_path, firmware_sample, capsys):
    root = str(tmp_path / "proj")
    run_cli("init", root)
    assert run_cli("-P", root, "analyze", firmware_sample) == 0
    output = capsys.readouterr().out
    assert "extracted" in output
    assert "bin/firmware_agent" in output


def test_doctor_reports_engines(capsys):
    assert run_cli("doctor") == 0
    output = capsys.readouterr().out
    assert "triage" in output
    assert "ghidra" in output


def test_schema_query_lists_predicates(capsys):
    root = None
    assert run_cli("query", "schema") in (0, 2)  # 2 when no project is present
    capsys.readouterr()


def test_missing_project_explains_itself(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert run_cli("query", "stats") == 2
    assert "aether init" in capsys.readouterr().err


def test_unknown_claim_id_is_a_clean_error(tmp_path, elf_sample, capsys):
    root = str(tmp_path / "proj")
    run_cli("init", root)
    run_cli("-P", root, "analyze", elf_sample)
    capsys.readouterr()
    assert run_cli("-P", root, "query", "claim", "clm_" + "0" * 32) != 0
    assert "unknown claim" in capsys.readouterr().err


# -- evaluation harness ------------------------------------------------------


def test_suite_files_are_well_formed():
    for name in sorted(os.listdir(SUITES)):
        if not name.endswith(".json"):
            continue
        suite = load_suite(os.path.join(SUITES, name))
        assert suite["expectations"]
        for expectation in suite["expectations"]:
            assert expectation.get("predicate"), f"{name}: expectation lacks a predicate"
            assert expectation.get("id"), f"{name}: expectation lacks an id"


def test_elf_suite_passes(elf_sample, ghidra_export_dir):
    """Phase 0 gate: structured claims validated against ground truth."""
    report = run_suite(load_suite(os.path.join(SUITES, "elf_sample.json")), base_dir=REPO_ROOT)
    unmet = [r.expectation_id for r in report.results if r.required and not r.satisfied]
    assert not unmet, f"unmet expectations: {unmet}"
    assert not report.forbidden_hits
    assert report.totals["recall"] == 1.0
    assert report.totals["integrity_problems"] == 0
    assert report.passed


def test_firmware_suite_passes(firmware_sample):
    report = run_suite(
        load_suite(os.path.join(SUITES, "firmware_image.json")), base_dir=REPO_ROOT
    )
    unmet = [r.expectation_id for r in report.results if r.required and not r.satisfied]
    assert not unmet, f"unmet expectations: {unmet}"
    assert not report.forbidden_hits
    assert report.passed


def test_harness_detects_a_missing_finding(elf_sample):
    """A suite that asks for something absent must fail, or it proves nothing."""
    suite = {
        "name": "negative-control",
        "target": {"path": "examples/firmware_agent.elf", "logical_path": "bin/x"},
        "pipeline": ["triage"],
        "expectations": [
            {
                "id": "impossible",
                "predicate": "embeds_component",
                "match": {"component": "nginx", "version": "1.99.0"},
            }
        ],
    }
    report = run_suite(suite, base_dir=REPO_ROOT)
    assert not report.passed
    assert report.totals["recall"] == 0.0


def test_harness_detects_a_false_positive(elf_sample):
    suite = {
        "name": "false-positive-control",
        "target": {"path": "examples/firmware_agent.elf", "logical_path": "bin/x"},
        "pipeline": ["triage"],
        "expectations": [],
        "forbidden": [
            {
                "id": "aws-key-should-not-be-found",
                "predicate": "contains_hardcoded_secret",
                "match": {"secret_kind": "aws_access_key"},
            }
        ],
    }
    report = run_suite(suite, base_dir=REPO_ROOT)
    assert not report.passed
    assert report.totals["forbidden_hits"] == 1


def test_harness_enforces_evidence_kind(elf_sample):
    """Right words, wrong evidence: the harness must not accept it."""
    suite = {
        "name": "evidence-control",
        "target": {"path": "examples/firmware_agent.elf", "logical_path": "bin/x"},
        "pipeline": ["triage"],
        "expectations": [
            {
                "id": "secret-backed-by-a-function",
                "predicate": "contains_hardcoded_secret",
                "match": {"secret_kind": "aws_access_key"},
                "evidence_kind": "function",
            }
        ],
    }
    report = run_suite(suite, base_dir=REPO_ROOT)
    assert not report.passed
    assert "evidence of kind" in report.results[0].detail


def test_harness_rejects_a_digest_mismatch(tmp_path):
    suite = {
        "name": "digest-control",
        "target": {"path": "examples/firmware_agent.elf", "sha256": "0" * 64},
        "pipeline": ["triage"],
        "expectations": [],
    }
    with pytest.raises(EvalError, match="digest mismatch"):
        run_suite(suite, base_dir=REPO_ROOT)


def test_missing_suite_file_is_reported():
    with pytest.raises(EvalError, match="no such suite"):
        load_suite("eval/suites/does-not-exist.json")


def test_eval_command_reports_pass(elf_sample, firmware_sample, ghidra_export_dir, capsys, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    assert run_cli("eval", "--base-dir", REPO_ROOT) == 0
    output = capsys.readouterr().out
    assert "suites passed" in output
    assert "FAIL" not in output


def test_run_suites_summary(elf_sample, firmware_sample, ghidra_export_dir):
    paths = [
        os.path.join(SUITES, name)
        for name in sorted(os.listdir(SUITES))
        if name.endswith(".json")
    ]
    _reports, summary = run_suites(paths, base_dir=REPO_ROOT)
    assert summary["failed"] == 0
    assert summary["recall"] == 1.0
    assert summary["required_total"] >= 30
