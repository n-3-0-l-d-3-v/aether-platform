"""Cross-binary sink reachability: chaining existing evidence into a new claim.

The chain is function_reached (QEMU) -> call xref (Ghidra) ->
imports_resolved_by (cartography linking). These tests build all three
ingredients from real fixtures and verify the chain produces claims exactly
where the evidence supports it, and nowhere else.
"""

from __future__ import annotations

import os

from aether.adapters.ghidra import GhidraAdapter
from aether.adapters.qemu import QemuAdapter
from aether.adapters.triage import TriageAdapter
from aether.cartography import link_imports
from aether.cartography.reachability import trace_cross_binary_reachability


def _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces):
    """A project with triage, Ghidra, and a QEMU trace all imported."""
    result = TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    object_id = result.objects[0]
    GhidraAdapter().import_directory(project, ghidra_export_dir, object_id=object_id)
    QemuAdapter().import_trace(
        project,
        os.path.join(qemu_traces, "firmware_agent.exec.log"),
        object_id=object_id,
    )
    return object_id


def _add_provider(project, symbols, path="lib/libc.so"):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        provider = rc.artifact(
            "file", {"path": path, "sha256": "c" * 64, "size": 1, "format": "elf", "source": "ingest"}
        )
        for index, symbol in enumerate(symbols):
            rc.artifact("export", {"name": symbol, "addr": 0x5000 + index * 0x10}, object_id=provider.artifact_id)
    return provider


def test_the_full_chain_produces_a_reachability_claim(project, elf_sample, ghidra_export_dir, qemu_traces):
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy", "system"])
    link_imports(project)

    result = trace_cross_binary_reachability(project)
    assert result.sinks_reached == 2
    assert not result.warnings

    claims = project.find_claims(predicate="cross_binary_reachable", limit=10)
    reached = {(c["statement"]["reached_via_function"], c["statement"]["symbol"]) for c in claims}
    assert ("handle_name", "strcpy") in reached
    assert ("run_diagnostics", "system") in reached
    assert project.check() == []


def test_evidence_chain_is_complete(project, elf_sample, ghidra_export_dir, qemu_traces):
    """Every link in the chain must be present as evidence: sink, trace, call, import."""
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy"])
    link_imports(project)
    trace_cross_binary_reachability(project)

    claim = project.find_claims(predicate="cross_binary_reachable", limit=1)[0]
    kinds = {project.get_artifact(ref["artifact_id"]).kind for ref in claim["evidence"]}
    assert "export" in kinds  # the sink
    assert "trace_hit" in kinds  # the runtime observation
    assert "xref" in kinds  # the call site
    assert "import" in kinds  # the resolved import


def test_no_reachability_without_an_observed_execution(project, elf_sample, ghidra_export_dir):
    """Ghidra and linking alone, no QEMU trace: nothing was seen running."""
    result_t = TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    GhidraAdapter().import_directory(project, ghidra_export_dir, object_id=result_t.objects[0])
    _add_provider(project, ["strcpy"])
    link_imports(project)

    result = trace_cross_binary_reachability(project)
    assert result.sinks_reached == 0
    assert any("function_reached" in w for w in result.warnings)
    assert not project.find_claims(predicate="cross_binary_reachable", limit=5)


def test_no_reachability_without_a_resolved_import(project, elf_sample, ghidra_export_dir, qemu_traces):
    """Execution observed, calls exist, but nothing on the project resolves them."""
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    # No provider file added, and link_imports is never run.
    result = trace_cross_binary_reachability(project)
    assert result.sinks_reached == 0
    assert any("imports_resolved_by" in w for w in result.warnings)


def test_a_function_that_never_ran_reaches_nothing(project, elf_sample, ghidra_export_dir, qemu_traces):
    """weak_token is defined and calls srand/rand, but never executed - no chain."""
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy", "system", "rand", "srand"])
    link_imports(project)
    trace_cross_binary_reachability(project)

    claims = project.find_claims(predicate="cross_binary_reachable", limit=10)
    via_functions = {c["statement"]["reached_via_function"] for c in claims}
    assert "weak_token" not in via_functions


def test_confidence_is_the_minimum_of_the_chained_claims(project, elf_sample, ghidra_export_dir, qemu_traces):
    """The chain is only as strong as its weakest link."""
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy"])
    link_imports(project)
    trace_cross_binary_reachability(project)

    reach_claim = project.find_claims(predicate="cross_binary_reachable", limit=1)[0]
    reached_claim = next(
        c
        for c in project.find_claims(predicate="function_reached", limit=10)
        if c["statement"]["name"] == "handle_name"
    )
    link_claim = next(
        c
        for c in project.find_claims(predicate="imports_resolved_by", limit=10)
        if c["statement"]["symbol"] == "strcpy"
    )
    expected = min(reached_claim["confidence"]["combined"], link_claim["confidence"]["combined"])
    assert reach_claim["confidence"]["combined"] == expected


def test_re_running_reachability_converges(project, elf_sample, ghidra_export_dir, qemu_traces):
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy", "system"])
    link_imports(project)
    trace_cross_binary_reachability(project)
    before = project.stats()["totals"]
    trace_cross_binary_reachability(project)
    after = project.stats()["totals"]
    assert after["claims"] == before["claims"]


def test_ambiguous_providers_produce_a_reachability_claim_per_candidate(
    project, elf_sample, ghidra_export_dir, qemu_traces
):
    """Two files exporting the same symbol: reachability follows both links."""
    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy"], path="lib/libc.so")
    _add_provider(project, ["strcpy"], path="lib/alt_libc.so")
    link_imports(project)
    trace_cross_binary_reachability(project)

    claims = [
        c
        for c in project.find_claims(predicate="cross_binary_reachable", limit=10)
        if c["statement"]["symbol"] == "strcpy"
    ]
    assert len(claims) == 2


# -- front ends -------------------------------------------------------------


def test_cli_reach_reports_sinks(tmp_path, elf_sample, ghidra_export_dir, qemu_traces, capsys):
    from aether.cli import main
    from aether.project import Project

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()

    project = Project.open(root)
    object_id = _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy", "system"])
    project.close()

    main(["-P", root, "map"])
    capsys.readouterr()

    assert main(["-P", root, "reach"]) == 0
    output = capsys.readouterr().out
    assert "cross-binary sink(s) reached" in output
    assert "strcpy" in output or "system" in output


def test_mcp_reach_returns_the_reachable_list(project, elf_sample, ghidra_export_dir, qemu_traces):
    from aether.mcp.server import MCPServer

    _fully_analysed(project, elf_sample, ghidra_export_dir, qemu_traces)
    _add_provider(project, ["strcpy", "system"])
    link_imports(project)

    server = MCPServer(project)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "aether_reach", "arguments": {}},
        }
    )["result"]
    payload = response["structuredContent"]
    assert payload["sinks_reached"] == 2
    symbols = {r["symbol"] for r in payload["reachable"]}
    assert symbols == {"strcpy", "system"}


def test_mcp_reach_is_hidden_and_refused_read_only(project):
    from aether.mcp.server import MCPServer

    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        rc.artifact(
            "file", {"path": "bin/app", "sha256": "d" * 64, "size": 1, "format": "elf", "source": "ingest"}
        )
    readonly = MCPServer(project, read_only=True)
    names = {
        t["name"]
        for t in readonly.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )["result"]["tools"]
    }
    assert "aether_reach" not in names
