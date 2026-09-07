"""The ecosystem-agent contract added in ADR 0011: agent.yaml, --health,
vault write with a human review gate, and the private-tier network guard.

These are new, additive capabilities layered on top of the existing evidence
graph - none of them touch claim/artifact enforcement, which stays covered by
test_evidence_model.py and test_mcp.py.
"""

from __future__ import annotations

import json
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# -- agent.yaml ---------------------------------------------------------------


def _load_flat_yaml(path: str) -> dict[str, str]:
    """Parse agent.yaml's flat `key: value` shape without adding a YAML
    dependency - Ultron has zero runtime dependencies (ADR 0001), and this
    manifest is deliberately simple enough not to need a real parser."""
    fields: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def test_agent_yaml_exists_at_repo_root():
    path = os.path.join(REPO_ROOT, "agent.yaml")
    assert os.path.isfile(path)


def test_agent_yaml_declares_the_required_fields():
    fields = _load_flat_yaml(os.path.join(REPO_ROOT, "agent.yaml"))
    assert fields["name"] == "Ultron"
    assert fields["role"] == "reverse-engineering-and-security"
    assert fields["default_sensitivity_tier"] == "private"
    assert fields["entrypoint"] == "ultron"
    assert fields["health_check_command"] == "ultron --health"
    assert fields["vault_write_path"] == "vault/Ultron/"
    assert fields["sandboxed"] == "true"


# -- ultron --health ------------------------------------------------------


def test_health_command_returns_well_shaped_json(capsys):
    from ultron.cli import main

    assert main(["--health"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "Ultron"
    assert payload["status"] == "ok"
    assert "version" in payload
    assert set(payload["backends"]) == {"ghidra", "binwalk"}
    for backend in payload["backends"].values():
        assert isinstance(backend["available"], bool)
        assert isinstance(backend["detail"], str)
    assert payload["test_suite_status"] in {"passing", "failing", "unknown"}
    assert "checked_at" in payload
    # last_run_at is None or a string; never absent as a key.
    assert "last_run_at" in payload


def test_health_flag_works_before_a_required_subcommand_would_normally_fire(capsys):
    """`ultron --health` must not need a project or any subcommand - a health
    poller should not have to satisfy the normal argparse subcommand
    requirement just to check liveness."""
    from ultron.cli import main

    exit_code = main(["--health"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert json.loads(out)["name"] == "Ultron"


def test_health_reports_project_last_run_when_pointed_at_one(tmp_path, elf_sample):
    from ultron.adapters.triage import TriageAdapter
    from ultron.health import collect_health
    from ultron.project import Project

    root = str(tmp_path / "proj")
    project = Project.create(root, "health-test")
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/agent")
    project.close()

    payload = collect_health(root)
    assert payload["last_run_at"] is not None


def test_health_command_registered_in_the_subcommand_list(capsys):
    """`ultron health` also works as an ordinary subcommand, for callers that
    prefer not to special-case a bare flag."""
    from ultron.cli import main

    assert main(["health"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "Ultron"


# -- vault write with a human review gate ------------------------------------


def test_vault_write_lands_in_pending_never_approved(tmp_path):
    from ultron import vault

    vault_root = str(tmp_path / "vault")
    note = vault.write_finding("Suspicious string", "Looks credential-shaped.", vault_root=vault_root)

    assert note.status == "pending"
    assert os.path.join(vault_root, "pending") in note.path or "pending" in note.path
    assert os.path.isfile(note.path)
    assert not vault.is_approved(note.path)


def test_vault_note_carries_frontmatter_defaulting_to_unapproved(tmp_path):
    from ultron import vault

    vault_root = str(tmp_path / "vault")
    note = vault.write_finding("Title", "Body", vault_root=vault_root, claim_ids=["clm_abc"], tags=["secrets"])

    with open(note.path, "r", encoding="utf-8") as handle:
        text = handle.read()
    assert "approved: false" in text
    assert "clm_abc" in text
    assert "secrets" in text


def test_vault_approve_moves_note_and_flips_frontmatter(tmp_path):
    from ultron import vault

    vault_root = str(tmp_path / "vault")
    note = vault.write_finding("Title", "Body", vault_root=vault_root)

    approved = vault.approve_note(os.path.basename(note.path), vault_root=vault_root)

    assert approved.status == "approved"
    assert "approved" in os.path.normpath(approved.path).split(os.sep)
    assert not os.path.isfile(note.path)  # moved, not copied
    assert vault.is_approved(approved.path)


def test_vault_list_never_reports_an_unmoved_note_as_approved(tmp_path):
    from ultron import vault

    vault_root = str(tmp_path / "vault")
    vault.write_finding("One", "Body one", vault_root=vault_root)
    vault.write_finding("Two", "Body two", vault_root=vault_root)

    notes = vault.list_notes(vault_root=vault_root)
    assert len(notes) == 2
    assert all(n.status == "pending" for n in notes)


def test_vault_approve_of_a_nonexistent_note_raises(tmp_path):
    from ultron import vault

    with pytest.raises(FileNotFoundError):
        vault.approve_note("does-not-exist.md", vault_root=str(tmp_path / "vault"))


def test_cli_vault_write_list_approve_round_trip(tmp_path, capsys):
    from ultron.cli import main

    vault_root = str(tmp_path / "vault")
    assert main(["vault", "write", "Finding title", "Finding body", "--vault-root", vault_root]) == 0
    capsys.readouterr()

    assert main(["--json", "vault", "list", "--vault-root", vault_root]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1
    assert listed[0]["status"] == "pending"

    note_path = listed[0]["path"]
    assert main(["--json", "vault", "approve", note_path, "--vault-root", vault_root]) == 0
    approved = json.loads(capsys.readouterr().out)
    assert approved["status"] == "approved"

    assert main(["--json", "vault", "list", "--vault-root", vault_root]) == 0
    listed_after = json.loads(capsys.readouterr().out)
    assert len(listed_after) == 1
    assert listed_after[0]["status"] == "approved"


# -- private-tier network refusal --------------------------------------------


def test_ollama_backend_accepts_localhost():
    from ultron.agents.backend import OllamaBackend

    OllamaBackend("llama3.2", host="http://localhost:11434")
    OllamaBackend("llama3.2", host="http://127.0.0.1:11434")


def test_ollama_backend_refuses_a_remote_host_by_default(monkeypatch):
    from ultron.agents.backend import OllamaBackend
    from ultron.network_policy import RemoteHostRefused

    monkeypatch.delenv("ULTRON_ALLOW_REMOTE_AGENT_HOST", raising=False)
    with pytest.raises(RemoteHostRefused):
        OllamaBackend("llama3.2", host="http://example.com:11434")


def test_ollama_backend_remote_host_allowed_with_explicit_override(monkeypatch):
    from ultron.agents.backend import OllamaBackend

    monkeypatch.setenv("ULTRON_ALLOW_REMOTE_AGENT_HOST", "1")
    OllamaBackend("llama3.2", host="http://example.com:11434")


def test_network_policy_rejects_non_1_override_values(monkeypatch):
    from ultron.agents.backend import OllamaBackend
    from ultron.network_policy import RemoteHostRefused

    monkeypatch.setenv("ULTRON_ALLOW_REMOTE_AGENT_HOST", "true")  # not exactly "1"
    with pytest.raises(RemoteHostRefused):
        OllamaBackend("llama3.2", host="http://example.com:11434")


def test_core_cli_imports_perform_no_network_call(tmp_path, elf_sample, monkeypatch):
    """Guards the zero-network claim structurally: patch every stdlib
    socket-opening entry point network code could plausibly reach, then
    exercise init/analyze/ask/health end to end. Any call through one of
    these would raise, since none of them are expected to fire - the whole
    point of the 'private' tier is that ordinary use never needs the
    network at all."""
    import socket
    import urllib.request

    def _boom(*args, **kwargs):
        raise AssertionError("unexpected network call during core analysis")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    from ultron.cli import main

    root = str(tmp_path / "proj")
    assert main(["init", root]) == 0
    assert main(["-P", root, "analyze", elf_sample]) == 0
    assert main(["-P", root, "--json", "ask", "is", "this", "binary", "hardened?"]) == 0
    assert main(["--health"]) == 0
