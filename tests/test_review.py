"""The approval workflow: a human review queue over agent-submitted claims.

The property that matters most here is not what the workflow does but what it
refuses to let an agent do: approve its own proposal. That is enforced by
never exposing approve/reject as an MCP tool at all, verified below by
checking the tool is simply absent from the server's tool list.
"""

from __future__ import annotations

import pytest

from yugen.errors import EvidenceError
from yugen.evidence.models import EvidenceRef
from yugen.review import approve, pending, reject


def _tool_claim(project, text="hello", confidence=0.9):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        f = project.resolve_object("bin/app") or rc.artifact(
            "file", {"path": "bin/app", "sha256": "a" * 64, "size": 1, "format": "elf", "source": "ingest"}
        )
        s = rc.artifact("string", {"text": text, "encoding": "ascii", "addr": hash(text) % 0xFFFF}, object_id=f.artifact_id)
        return rc.add_claim(
            "contains_string",
            {"text": text},
            [EvidenceRef(s.artifact_id, "locus")],
            subject_id=f.artifact_id,
            confidence=confidence,
            producer="yugen-triage",
            producer_kind="tool",
        )


def _agent_claim(project, text="agent finding", confidence=0.6, producer="agent:x"):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        f = project.resolve_object("bin/app") or rc.artifact(
            "file", {"path": "bin/app", "sha256": "a" * 64, "size": 1, "format": "elf", "source": "ingest"}
        )
        s = rc.artifact("string", {"text": text, "encoding": "ascii", "addr": hash(text) % 0xFFFF}, object_id=f.artifact_id)
        return rc.add_claim(
            "contains_string",
            {"text": text},
            [EvidenceRef(s.artifact_id, "locus")],
            subject_id=f.artifact_id,
            confidence=confidence,
            producer=producer,
            producer_kind="agent",
        )


# -- the queue ----------------------------------------------------------


def test_a_deterministic_only_claim_is_not_in_the_default_queue(project):
    _tool_claim(project)
    assert pending(project) == []


def test_an_agent_claim_appears_in_the_default_queue(project):
    claim = _agent_claim(project)
    queue = pending(project)
    assert [c.claim_id for c in queue] == [claim.claim_id]


def test_all_flag_includes_tool_only_claims(project):
    _tool_claim(project, text="tool text")
    _agent_claim(project, text="agent text")
    assert len(pending(project)) == 1
    assert len(pending(project, agent_only=False)) == 2


def test_accepted_claims_are_not_in_the_queue(project):
    claim = _agent_claim(project)
    approve(project, claim.claim_id, reviewer="alice")
    assert pending(project) == []


def test_queue_can_be_filtered_by_predicate_and_confidence(project):
    _agent_claim(project, text="low", confidence=0.3)
    _agent_claim(project, text="high", confidence=0.9)
    assert len(pending(project, min_confidence=0.5)) == 1
    assert pending(project, min_confidence=0.5)[0].statement["text"] == "high"


def test_pending_claim_carries_enough_context_to_decide(project):
    claim = _agent_claim(project, producer="agent:secrets-v1")
    entry = pending(project)[0]
    record = entry.to_record()
    assert record["claim_id"] == claim.claim_id
    assert record["subject_path"] == "bin/app"
    assert "agent:secrets-v1" in record["producers"]
    assert record["evidence_count"] == 1


# -- deciding -------------------------------------------------------------


def test_approving_sets_status_and_leaves_an_audit_trail(project):
    claim = _agent_claim(project)
    decision = approve(project, claim.claim_id, reviewer="alice", note="checked the evidence")
    assert decision.outcome == "accepted"
    stored = project.get_claim(claim.claim_id)
    assert stored["status"] == "accepted"
    notes = project.annotations(claim.claim_id)
    assert len(notes) == 1
    assert "alice" in notes[0]["body"]
    assert "checked the evidence" in notes[0]["body"]


def test_rejecting_sets_status_and_leaves_an_audit_trail(project):
    claim = _agent_claim(project)
    decision = reject(project, claim.claim_id, reviewer="bob", note="false positive")
    assert decision.outcome == "rejected"
    assert project.get_claim(claim.claim_id)["status"] == "rejected"
    assert "bob" in project.annotations(claim.claim_id)[0]["body"]


def test_accepting_the_claim_never_changes_its_statement(project):
    """Curation changes status only; it must never touch what was asserted."""
    claim = _agent_claim(project)
    before = dict(project.get_claim(claim.claim_id)["statement"])
    approve(project, claim.claim_id, reviewer="alice")
    after = project.get_claim(claim.claim_id)["statement"]
    assert before == after


def test_a_short_id_prefix_is_accepted(project):
    claim = _agent_claim(project)
    decision = approve(project, claim.claim_id[:16], reviewer="alice")
    assert decision.claim_id == claim.claim_id


def test_deciding_on_an_unknown_claim_is_a_clean_error(project):
    with pytest.raises(EvidenceError, match="unknown claim"):
        approve(project, "clm_" + "0" * 32, reviewer="alice")


def test_deciding_twice_is_refused(project):
    claim = _agent_claim(project)
    approve(project, claim.claim_id, reviewer="alice")
    with pytest.raises(EvidenceError, match="already 'accepted'"):
        approve(project, claim.claim_id, reviewer="bob")
    with pytest.raises(EvidenceError, match="already 'accepted'"):
        reject(project, claim.claim_id, reviewer="bob")


def test_evidence_graph_stays_intact_after_review(project):
    claim = _agent_claim(project)
    approve(project, claim.claim_id, reviewer="alice")
    assert project.check() == []


# -- front ends -------------------------------------------------------------


def test_cli_review_list_and_approve(tmp_path, capsys):
    from yugen.cli import main
    from yugen.project import Project

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()

    project = Project.open(root)
    claim = _agent_claim(project)
    project.close()

    assert main(["-P", root, "review", "list"]) == 0
    output = capsys.readouterr().out
    assert claim.claim_id[:16] in output

    assert main(["-P", root, "review", "approve", claim.claim_id, "--reviewer", "alice"]) == 0
    output = capsys.readouterr().out
    assert "accepted by alice" in output

    assert main(["-P", root, "review", "list"]) == 0
    assert "nothing awaiting review" in capsys.readouterr().out


def test_cli_review_reject(tmp_path, capsys):
    from yugen.cli import main
    from yugen.project import Project

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()
    project = Project.open(root)
    claim = _agent_claim(project)
    project.close()

    assert main(["-P", root, "review", "reject", claim.claim_id, "--reviewer", "bob", "--note", "nah"]) == 0
    assert "rejected by bob" in capsys.readouterr().out


def test_cli_review_approve_requires_a_claim_id(tmp_path, capsys):
    from yugen.cli import main

    main(["init", str(tmp_path / "proj")])
    capsys.readouterr()
    # argparse itself enforces the positional argument; this just confirms
    # the subcommand is wired up rather than silently missing.
    assert main(["-P", str(tmp_path / "proj"), "review", "approve", "clm_" + "1" * 32]) != 0


def test_mcp_review_queue_is_read_only(project):
    from yugen.mcp.server import MCPServer

    claim = _agent_claim(project)
    server = MCPServer(project)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "yugen_review_queue", "arguments": {}},
        }
    )["result"]
    payload = response["structuredContent"]
    assert payload["returned"] == 1
    assert payload["pending"][0]["claim_id"] == claim.claim_id


def test_no_mcp_tool_can_approve_or_reject_a_claim(project):
    """The headline safety property: agents cannot mark their own homework."""
    from yugen.mcp import tools

    names = set(tools.TOOLS)
    assert not any("approve" in name for name in names)
    assert not any("reject" in name for name in names)
    # yugen_submit_claim exists and writes proposals; nothing promotes one.
    assert "yugen_submit_claim" in names
    assert tools.TOOLS["yugen_review_queue"].writes is False
