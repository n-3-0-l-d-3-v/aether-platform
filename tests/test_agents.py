"""The secrets/indicators triage agent, and its local-only LLM backends.

No test here ever makes a real network call. `FakeLLMBackend` is fully
deterministic; `OllamaBackend`'s tests mock `urllib.request.urlopen` at the
boundary so they exercise the real parsing and error-handling code without
needing a running Ollama server - in CI or anywhere else.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from ultron.agents.backend import DEFAULT_OLLAMA_HOST, FakeLLMBackend, OllamaBackend, probe
from ultron.errors import AdapterUnavailable
from ultron.evidence.models import EvidenceRef
from ultron.review import pending


def _make_file(rc, path="bin/app"):
    return rc.artifact(
        "file",
        {"path": path, "sha256": "a" * 64, "size": 1, "format": "elf", "source": "ingest"},
    )


def _make_string(rc, file_artifact, text, addr):
    return rc.artifact("string", {"text": text, "encoding": "ascii", "addr": addr}, object_id=file_artifact.artifact_id)


def _seed_strings(project, texts):
    """Write a file artifact and one string artifact per text; return the file id."""
    from ultron.agents.secrets import TOOL_NAME  # noqa: F401  (import sanity)

    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        f = _make_file(rc)
        for offset, text in enumerate(texts):
            _make_string(rc, f, text, addr=0x1000 + offset)
        return f.artifact_id


# -- run_secrets_triage: happy paths -------------------------------------


def test_a_flagged_secret_becomes_one_proposed_claim(project):
    from ultron.agents.secrets import run_secrets_triage

    object_id = _seed_strings(project, ["totally_normal_string", "sk_live_obfuscated_credential_blob"])

    def responder(prompt: str) -> str:
        # The candidate at index 1 is the "obfuscated credential".
        return json.dumps(
            [{"index": 1, "predicate": "contains_hardcoded_secret", "kind": "api_token", "confidence": 0.8}]
        )

    backend = FakeLLMBackend(responder)
    result = run_secrets_triage(project, backend, object_id=object_id)

    assert result.considered == 2
    assert len(result.proposed_claim_ids) == 1
    claim = project.get_claim(result.proposed_claim_ids[0])
    assert claim["predicate"] == "contains_hardcoded_secret"
    assert claim["status"] == "proposed"
    assert claim["statement"]["secret_kind"] == "api_token"
    assert claim["statement"]["detector"] == "agent:ultron-agent-secrets"
    # Never the raw value, always a redacted preview.
    assert "sk_live_obfuscated_credential_blob" not in claim["statement"]["redacted_preview"]
    producer_kinds = {a["producer_kind"] for a in claim["attestations"]}
    assert producer_kinds == {"agent"}

    queue = pending(project)
    assert [c.claim_id for c in queue] == [claim["id"]]


def test_a_flagged_suspicious_string_becomes_one_proposed_claim(project):
    from ultron.agents.secrets import run_secrets_triage

    object_id = _seed_strings(project, ["weird-shaped-endpoint-reference"])

    backend = FakeLLMBackend(
        json.dumps([{"index": 0, "predicate": "suspicious_string", "kind": "url", "confidence": 0.7}])
    )
    result = run_secrets_triage(project, backend, object_id=object_id)

    assert len(result.proposed_claim_ids) == 1
    claim = project.get_claim(result.proposed_claim_ids[0])
    assert claim["predicate"] == "suspicious_string"
    assert claim["status"] == "proposed"
    assert claim["statement"]["category"] == "url"
    assert claim["statement"]["detector"] == "agent:ultron-agent-secrets"


# -- defensive parsing ----------------------------------------------------


def test_malformed_json_is_skipped_not_raised(project):
    from ultron.agents.secrets import run_secrets_triage

    object_id = _seed_strings(project, ["one string"])
    backend = FakeLLMBackend("this is not json at all")
    result = run_secrets_triage(project, backend, object_id=object_id)

    assert result.proposed_claim_ids == ()
    assert result.skipped_malformed == 1


def test_malformed_items_within_a_valid_list_are_skipped_individually(project):
    from ultron.agents.secrets import run_secrets_triage

    object_id = _seed_strings(project, ["string a", "string b"])
    backend = FakeLLMBackend(
        json.dumps(
            [
                {"index": 0, "predicate": "contains_hardcoded_secret", "kind": "not_a_real_kind", "confidence": 0.9},
                {"index": 1, "predicate": "suspicious_string", "kind": "url", "confidence": 0.9},
            ]
        )
    )
    result = run_secrets_triage(project, backend, object_id=object_id)

    assert len(result.proposed_claim_ids) == 1
    claim = project.get_claim(result.proposed_claim_ids[0])
    assert claim["statement"]["category"] == "url"


def test_one_malformed_batch_does_not_abort_a_later_batch(project):
    from ultron.agents.secrets import run_secrets_triage

    texts = [f"string {i}" for i in range(4)]
    object_id = _seed_strings(project, texts)

    calls = {"n": 0}

    def responder(prompt: str) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return "garbage, not json"
        return json.dumps([{"index": 0, "predicate": "suspicious_string", "kind": "url", "confidence": 0.9}])

    backend = FakeLLMBackend(responder)
    result = run_secrets_triage(project, backend, object_id=object_id, batch_size=2)

    assert calls["n"] == 2
    assert result.skipped_malformed == 2  # first batch (size 2) wholly skipped
    assert len(result.proposed_claim_ids) == 1


# -- confidence and cap filtering -----------------------------------------


def test_low_confidence_items_are_skipped_and_counted(project):
    from ultron.agents.secrets import run_secrets_triage

    object_id = _seed_strings(project, ["quiet string"])
    backend = FakeLLMBackend(
        json.dumps([{"index": 0, "predicate": "suspicious_string", "kind": "url", "confidence": 0.1}])
    )
    result = run_secrets_triage(project, backend, object_id=object_id, min_confidence=0.5)

    assert result.proposed_claim_ids == ()
    assert result.skipped_low_confidence == 1


def test_max_claims_bounds_proposals_even_when_more_are_flagged(project):
    from ultron.agents.secrets import run_secrets_triage

    texts = [f"secret-looking-{i}" for i in range(5)]
    object_id = _seed_strings(project, texts)

    backend = FakeLLMBackend(
        json.dumps(
            [
                {"index": i, "predicate": "suspicious_string", "kind": "url", "confidence": 0.9}
                for i in range(5)
            ]
        )
    )
    result = run_secrets_triage(project, backend, object_id=object_id, max_claims=2, batch_size=20)

    assert len(result.proposed_claim_ids) == 2


# -- existing claims are not re-flagged ------------------------------------


def test_a_string_already_claimed_is_not_re_flagged(project):
    from ultron.agents.secrets import run_secrets_triage

    with project.run(tool="ultron-triage", tool_version="1", adapter="triage") as rc:
        f = _make_file(rc)
        already = _make_string(rc, f, "AKIAABCDEFGHIJKLMNOP", addr=0x2000)
        rc.add_claim(
            "contains_hardcoded_secret",
            {"secret_kind": "aws_access_key", "detector": "rule:aws-access-key-id", "redacted_preview": "AKIA****"},
            [EvidenceRef(already.artifact_id, "locus")],
            subject_id=f.artifact_id,
            confidence=0.95,
            producer="ultron-triage",
            producer_kind="tool",
        )
        fresh = _make_string(rc, f, "another unrelated string", addr=0x2100)
        object_id = f.artifact_id

    backend = FakeLLMBackend(
        json.dumps([{"index": 0, "predicate": "suspicious_string", "kind": "url", "confidence": 0.9}])
    )
    result = run_secrets_triage(project, backend, object_id=object_id)

    assert result.skipped_existing == 1
    assert result.considered == 1  # only the fresh string was sent to the model


# -- backend: FakeLLMBackend ------------------------------------------------


def test_fake_backend_returns_fixed_string():
    backend = FakeLLMBackend("[]")
    assert backend.complete("anything") == "[]"


def test_fake_backend_calls_responder_with_the_prompt():
    seen = {}

    def responder(prompt):
        seen["prompt"] = prompt
        return "[]"

    backend = FakeLLMBackend(responder)
    backend.complete("my prompt here")
    assert seen["prompt"] == "my prompt here"


# -- backend: OllamaBackend, network mocked --------------------------------


def _fake_response(body: dict) -> MagicMock:
    response = MagicMock()
    response.status = 200
    response.read.return_value = json.dumps(body).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def test_ollama_backend_requires_a_model_name():
    with pytest.raises(ValueError):
        OllamaBackend("")


def test_ollama_backend_parses_a_successful_response():
    backend = OllamaBackend("llama3.2", host="http://localhost:11434")
    with patch("urllib.request.urlopen", return_value=_fake_response({"response": "[]"})) as mocked:
        result = backend.complete("do the thing")
    assert result == "[]"
    request = mocked.call_args[0][0]
    assert request.full_url == "http://localhost:11434/api/generate"
    sent = json.loads(request.data.decode("utf-8"))
    assert sent["model"] == "llama3.2"
    assert sent["stream"] is False


def test_ollama_backend_raises_adapter_unavailable_on_connection_failure():
    backend = OllamaBackend("llama3.2")
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        with pytest.raises(AdapterUnavailable, match="Ollama"):
            backend.complete("do the thing")


def test_ollama_backend_probe_reports_unreachable_cleanly():
    backend = OllamaBackend("llama3.2", host=DEFAULT_OLLAMA_HOST)
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        availability = probe(backend)
    assert availability.available is False
    assert "ollama.com" in availability.remedy.lower() or "ollama" in availability.remedy.lower()


def test_ollama_backend_raises_on_malformed_json_body():
    backend = OllamaBackend("llama3.2")
    bad_response = MagicMock()
    bad_response.status = 200
    bad_response.read.return_value = b"not json"
    bad_response.__enter__.return_value = bad_response
    bad_response.__exit__.return_value = False
    with patch("urllib.request.urlopen", return_value=bad_response):
        with pytest.raises(AdapterUnavailable):
            backend.complete("do the thing")


# -- CLI: clean failure when Ollama is unreachable -------------------------


def test_cli_agent_secrets_fails_cleanly_when_ollama_is_unreachable(tmp_path, capsys):
    from ultron.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()

    # Port 1 refuses connections immediately on every platform this runs on;
    # no mocking needed and no real server required.
    exit_code = main(
        [
            "-P",
            root,
            "agent",
            "secrets",
            "--model",
            "llama3.2",
            "--host",
            "http://127.0.0.1:1",
        ]
    )
    assert exit_code != 0
    err = capsys.readouterr().err
    assert "agent secrets" in err
    assert "Ollama" in err


def test_cli_agent_secrets_help_does_not_crash():
    from ultron.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main(["agent", "secrets", "--help"])
    assert exc_info.value.code == 0


# -- the MCP surface is unchanged ------------------------------------------


def test_no_mcp_tool_exposes_the_secrets_agent():
    """First Phase 3 specialist agent is CLI-only; no new MCP tool exists."""
    from ultron.mcp import tools

    names = set(tools.TOOLS)
    assert not any("agent" in name.lower() for name in names)
