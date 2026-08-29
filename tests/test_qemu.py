"""QEMU reachability: trace parsing, attribution, and the execution guard."""

from __future__ import annotations

import os
import runpy
import sys

import pytest

from aether.adapters.ghidra import GhidraAdapter
from aether.adapters.qemu import QemuAdapter
from aether.adapters.qemu import trace as trace_parser
from aether.adapters.triage import TriageAdapter
from aether.errors import AdapterError

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRACE_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "qemu")


@pytest.fixture(scope="session")
def qemu_traces(elf_sample: str) -> str:
    """Recorded QEMU logs consistent with the ELF sample's real addresses."""
    if not os.path.isfile(os.path.join(TRACE_DIR, "firmware_agent.exec.log")):
        script = os.path.join(REPO_ROOT, "tests", "fixtures", "make_qemu_fixture.py")
        saved = sys.argv
        sys.argv = [script]
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise
        finally:
            sys.argv = saved
    return TRACE_DIR


@pytest.fixture()
def analysed(project, elf_sample, ghidra_export_dir):
    """A project with functions recovered, ready to attribute a trace to."""
    result = TriageAdapter().analyze(
        project, elf_sample, logical_path="bin/firmware_agent"
    )
    GhidraAdapter().import_directory(
        project, ghidra_export_dir, object_id=result.objects[0]
    )
    return project, result.objects[0]


# -- trace parsing ----------------------------------------------------------


def test_exec_format_is_parsed(qemu_traces):
    parsed = trace_parser.parse_trace_file(
        os.path.join(qemu_traces, "firmware_agent.exec.log")
    )
    assert parsed.format == "exec"
    assert parsed.addresses == {0x400140, 0x400158, 0x400180}
    counts = {event.addr: event.hit_count for event in parsed.events}
    assert counts[0x400180] == 6


def test_in_asm_format_is_parsed_and_flagged(qemu_traces):
    """in_asm counts translations, not executions, and must say so."""
    parsed = trace_parser.parse_trace_file(
        os.path.join(qemu_traces, "firmware_agent.in_asm.log")
    )
    assert parsed.format == "in_asm"
    assert 0x400140 in parsed.addresses
    assert any("translation counts" in w for w in parsed.warnings)


def test_unrecognised_log_is_reported_not_guessed():
    parsed = trace_parser.parse_trace("this is not a qemu log at all\n")
    assert parsed.format == "none"
    assert not parsed.events
    assert parsed.warnings


def test_empty_log_is_handled():
    parsed = trace_parser.parse_trace("")
    assert parsed.format == "none"
    assert parsed.warnings


def test_exec_format_wins_when_both_are_present():
    """exec records every block entry; in_asm records each block once."""
    mixed = (
        "IN: main\n"
        "0x0000000000400180:  48 89 e5   mov %rsp,%rbp\n"
        "Trace 0: 0x7f00 [00000000/0000000000400180/00000033/ff000000]\n"
    )
    assert trace_parser.parse_trace(mixed).format == "exec"


def test_distinct_address_cap_keeps_the_hottest():
    log = "\n".join(
        f"Trace {i}: 0x7f00 [00000000/{0x400000 + i:016x}/00000033/ff000000]"
        for i in range(50)
    )
    parsed = trace_parser.parse_trace(log, max_addresses=10)
    assert parsed.truncated
    assert len(parsed.events) == 10
    assert any("distinct addresses" in w for w in parsed.warnings)


def test_load_base_inference_finds_the_offset():
    base = trace_parser.infer_load_base(
        addresses={0x4000400140, 0x4000400158, 0x4000400180},
        function_starts={0x400140, 0x400158, 0x400180},
    )
    assert base == 0x4000000000


def test_load_base_inference_declines_on_thin_evidence():
    """An unaligned trace must yield no claims, not wrong ones."""
    assert trace_parser.infer_load_base(addresses=set(), function_starts={0x1000}) is None
    assert (
        trace_parser.infer_load_base(
            addresses={0xDEAD0000}, function_starts={0x400140}, minimum_hits=3
        )
        is None
    )


# -- attribution ------------------------------------------------------------


def test_reached_functions_become_evidence_backed_claims(analysed, qemu_traces):
    project, object_id = analysed
    result = QemuAdapter().import_trace(
        project,
        os.path.join(qemu_traces, "firmware_agent.exec.log"),
        object_id=object_id,
        run_label="./firmware_agent AAAA",
    )
    assert result.details["functions_reached"] == 3

    claims = project.find_claims(predicate="function_reached", limit=20)
    assert {c["statement"]["name"] for c in claims} == {
        "main",
        "handle_name",
        "run_diagnostics",
    }
    for claim in claims:
        kinds = {
            (ref["role"], project.get_artifact(ref["artifact_id"]).kind)
            for ref in claim["evidence"]
        }
        assert ("locus", "function") in kinds
        assert ("support", "trace_hit") in kinds
    assert project.check() == []


def test_an_unreached_function_produces_no_claim(analysed, qemu_traces):
    """The negative case is the whole point of reachability evidence."""
    project, object_id = analysed
    QemuAdapter().import_trace(
        project,
        os.path.join(qemu_traces, "firmware_agent.exec.log"),
        object_id=object_id,
    )
    reached = {
        c["statement"]["name"]
        for c in project.find_claims(predicate="function_reached", limit=20)
    }
    assert "weak_token" not in reached

    defined = {
        c["statement"]["name"]
        for c in project.find_claims(predicate="defines_function", limit=20)
    }
    assert "weak_token" in defined, "the function is known, it just never ran"


def test_a_position_independent_trace_is_realigned(analysed, qemu_traces):
    project, object_id = analysed
    result = QemuAdapter().import_trace(
        project,
        os.path.join(qemu_traces, "firmware_agent.pie.log"),
        object_id=object_id,
    )
    assert result.details["load_base"] == 0x4000000000
    assert result.details["functions_reached"] == 3
    assert any("load base" in w for w in result.warnings)


def test_the_same_run_imported_twice_converges(analysed, qemu_traces):
    project, object_id = analysed
    log = os.path.join(qemu_traces, "firmware_agent.exec.log")
    QemuAdapter().import_trace(project, log, object_id=object_id, run_label="run")
    before = project.stats()["totals"]
    QemuAdapter().import_trace(project, log, object_id=object_id, run_label="run")
    after = project.stats()["totals"]
    assert after["artifacts"] == before["artifacts"]
    assert after["claims"] == before["claims"]


def test_a_trace_without_functions_warns_instead_of_failing(project, elf_sample, qemu_traces):
    """Triage alone recovers no functions; the trace is kept, claims are not."""
    result = TriageAdapter().analyze(project, elf_sample, logical_path="bin/agent")
    outcome = QemuAdapter().import_trace(
        project,
        os.path.join(qemu_traces, "firmware_agent.exec.log"),
        object_id=result.objects[0],
    )
    assert outcome.details["functions_known"] == 0
    assert any("no function artifacts" in w for w in outcome.warnings)
    assert not project.find_claims(predicate="function_reached", limit=5)


def test_import_requires_something_to_attach_to(project, qemu_traces):
    with pytest.raises(AdapterError, match="attached to something"):
        QemuAdapter().import_trace(
            project, os.path.join(qemu_traces, "firmware_agent.exec.log")
        )


def test_missing_log_is_a_clean_error(project):
    with pytest.raises(AdapterError, match="no such trace log"):
        QemuAdapter().import_trace(project, "does-not-exist.log", object_id="art_x")


# -- the execution guard ----------------------------------------------------


def test_execution_is_refused_without_explicit_consent(project, elf_sample):
    """qemu-user is not a sandbox, so running a target is never implicit."""
    with pytest.raises(AdapterError, match="refusing to execute"):
        QemuAdapter().analyze(project, elf_sample, allow_execution=False)


def test_the_refusal_explains_the_risk_and_the_alternative(project, elf_sample):
    with pytest.raises(AdapterError) as raised:
        QemuAdapter().analyze(project, elf_sample)
    message = str(raised.value)
    assert "sandbox" in message
    assert "host kernel" in message


def test_cli_trace_refuses_without_the_flag(tmp_path, elf_sample, capsys):
    from aether.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()
    assert main(["-P", root, "trace", elf_sample]) != 0
    assert "--allow-execution" in capsys.readouterr().err


def test_probe_explains_how_to_install_when_absent():
    availability = QemuAdapter(binary=None).probe()
    if not availability.available:
        assert "qemu-user" in availability.remedy
        assert "import-trace" in availability.remedy
        assert availability.cost


def test_doctor_reports_qemu(capsys):
    from aether.cli import main

    assert main(["--json", "doctor"]) == 0
    import json

    report = json.loads(capsys.readouterr().out)
    assert "qemu" in report
