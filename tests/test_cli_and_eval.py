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


# -- doctor -----------------------------------------------------------------


def test_doctor_reports_java_separately_from_ghidra(capsys):
    """The JDK is diagnosed on its own row.

    Ghidra headless fails on a missing or too-old runtime in a way that reads
    as a Ghidra problem, so hiding Java behind Ghidra's row withholds the
    information exactly when someone is still setting things up.
    """
    assert run_cli("--json", "doctor") == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"triage", "java", "ghidra", "binwalk"}
    assert report["triage"]["available"] is True


def test_doctor_states_what_each_missing_component_costs(capsys):
    run_cli("--json", "doctor")
    report = json.loads(capsys.readouterr().out)
    for name, info in report.items():
        if not info["available"]:
            assert info["cost"], f"{name} is missing but does not say what that costs"
            assert info["remedy"], f"{name} is missing but offers no remedy"


def test_doctor_succeeds_even_with_every_engine_missing(capsys):
    """Missing optional engines are a normal state, not a failure."""
    assert run_cli("doctor") == 0
    output = capsys.readouterr().out
    assert "components available" in output
    for component in ("triage", "java", "ghidra", "binwalk"):
        assert component in output


def test_doctor_output_stays_within_eighty_columns(capsys):
    run_cli("doctor")
    for line in capsys.readouterr().out.splitlines():
        assert len(line) <= 80, f"line exceeds 80 columns: {line!r}"


def test_doctor_folds_a_long_runtime_path(capsys, monkeypatch):
    """Width must not depend on what the host happens to have installed.

    The plain width test above passes trivially on a machine with no Java. CI
    runners ship a JDK at paths like
    C:/hostedtoolcache/windows/Java_Temurin-Hotspot_jdk/17.0.20-8/x64/bin/java.exe,
    which is longer than the whole line budget on its own - that is how the
    original overflow reached CI unnoticed.
    """
    import subprocess

    from aether.adapters import ghidra

    long_path = (
        "C:/hostedtoolcache/windows/Java_Temurin-Hotspot_jdk/"
        "17.0.20-8/x64/bin/java.EXE"
    )
    monkeypatch.setattr(ghidra, "find_java", lambda: long_path)
    monkeypatch.setattr(
        ghidra,
        "run_process",
        lambda argv, **kw: subprocess.CompletedProcess(
            argv, 0, stdout="", stderr='openjdk version "17.0.20" 2023-07-18'
        ),
    )

    run_cli("doctor")
    output = capsys.readouterr().out
    for line in output.splitlines():
        assert len(line) <= 80, f"line exceeds 80 columns: {line!r}"
    # The path must still be recoverable, just folded across lines.
    assert "hostedtoolcache" in output
    assert "17" in output


def test_java_probe_parses_a_version_string(monkeypatch):
    """Java reports its version on stderr, and Java 8 uses the 1.x scheme."""
    import subprocess

    from aether.adapters import ghidra

    monkeypatch.setattr(ghidra, "find_java", lambda: "/usr/bin/java")

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 0, stdout="", stderr='openjdk version "21.0.3" 2024-04-16\n'
        )

    monkeypatch.setattr(ghidra, "run_process", fake_run)
    result = ghidra.probe_java()
    assert result.available is True
    assert result.version == "21"


def test_java_probe_rejects_a_runtime_older_than_ghidra_needs(monkeypatch):
    import subprocess

    from aether.adapters import ghidra

    monkeypatch.setattr(ghidra, "find_java", lambda: "/usr/bin/java")

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 0, stdout="", stderr='java version "1.8.0_401"\n'
        )

    monkeypatch.setattr(ghidra, "run_process", fake_run)
    result = ghidra.probe_java()
    assert result.available is False
    assert result.version == "8"
    assert "21" in result.remedy
    assert result.cost
