"""MCP protocol and tool surface.

The tools are the contract agents work against, so the tests cover both the
wire protocol and - more importantly - that an agent cannot use them to get a
free-text finding into the graph.
"""

from __future__ import annotations

import io
import json

import pytest

from aether.adapters.triage import TriageAdapter
from aether.mcp import tools
from aether.mcp.server import PROTOCOL_VERSION, MCPServer


@pytest.fixture()
def server(project, elf_sample):
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    return MCPServer(project)


def request(server: MCPServer, method: str, params=None, message_id=1):
    return server.handle_message(
        {"jsonrpc": "2.0", "id": message_id, "method": method, "params": params or {}}
    )


def call(server: MCPServer, name: str, arguments=None):
    response = request(server, "tools/call", {"name": name, "arguments": arguments or {}})
    return response["result"]


# -- protocol ---------------------------------------------------------------


def test_initialize_advertises_tools_and_guidance(server):
    result = request(server, "initialize", {"protocolVersion": PROTOCOL_VERSION})["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["capabilities"]["tools"] is not None
    assert result["serverInfo"]["name"] == "aether"
    assert "aether_submit_claim" in result["instructions"]


def test_older_protocol_versions_are_honoured(server):
    result = request(server, "initialize", {"protocolVersion": "2024-11-05"})["result"]
    assert result["protocolVersion"] == "2024-11-05"


def test_unknown_protocol_version_falls_back_to_ours(server):
    result = request(server, "initialize", {"protocolVersion": "1999-01-01"})["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION


def test_notifications_get_no_response(server):
    assert server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    ) is None
    assert server.initialized is True


def test_ping_and_empty_capability_listings(server):
    assert request(server, "ping")["result"] == {}
    assert request(server, "prompts/list")["result"]["prompts"] == []
    assert request(server, "resources/list")["result"]["resources"] == []


def test_unknown_method_is_a_jsonrpc_error(server):
    response = request(server, "tools/frobnicate")
    assert response["error"]["code"] == -32601


def test_non_jsonrpc_message_is_rejected(server):
    response = server.handle_message({"id": 1, "method": "ping"})
    assert response["error"]["code"] == -32600


def test_every_tool_has_a_usable_schema(server):
    listed = request(server, "tools/list")["result"]["tools"]
    assert len(listed) == len(tools.TOOLS)
    for descriptor in listed:
        assert descriptor["description"].strip()
        schema = descriptor["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        for name in schema.get("required", []):
            assert name in schema["properties"]


def test_serve_reads_newline_delimited_json(project, elf_sample):
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    stdin = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
    )
    stdout = io.BytesIO()
    MCPServer(project).serve(stdin, stdout)

    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert [message["id"] for message in lines] == [1, 2]
    assert lines[1]["result"]["tools"]


def test_malformed_json_does_not_kill_the_transport(project):
    stdin = io.BytesIO(b"{ not json\n" + b'{"jsonrpc":"2.0","id":9,"method":"ping"}\n')
    stdout = io.BytesIO()
    MCPServer(project).serve(stdin, stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["id"] == 9


# -- read tools -------------------------------------------------------------


def test_project_info_reports_engine_availability(server):
    payload = call(server, "aether_project_info")["structuredContent"]
    assert payload["totals"]["artifacts"] > 0
    assert payload["engines"]["triage"]["available"] is True
    assert "ghidra" in payload["engines"]


def test_list_and_get_object(server):
    listed = call(server, "aether_list_objects")["structuredContent"]
    assert listed["objects"][0]["format"] == "elf"

    detail = call(server, "aether_get_object", {"object": "firmware_agent"})[
        "structuredContent"
    ]
    assert detail["object"]["kind"] == "file"
    assert detail["claim_count"] > 0
    assert detail["highest_confidence_claims"]


def test_search_strings_returns_locations(server):
    payload = call(server, "aether_search_strings", {"query": "AKIA"})["structuredContent"]
    assert payload["matches"]
    match = payload["matches"][0]
    assert match["addr"].startswith("0x")
    assert match["in_file"] == "bin/firmware_agent"


def test_claims_resolve_to_their_evidence(server):
    found = call(server, "aether_find_claims", {"predicate": "contains_hardcoded_secret"})
    claim_id = found["structuredContent"]["claims"][0]["claim_id"]

    detail = call(server, "aether_get_claim", {"claim_id": claim_id})["structuredContent"]
    assert detail["evidence"]
    assert detail["evidence"][0]["kind"] == "string"
    assert detail["claim"]["attestations"]


def test_address_query_finds_the_covering_artifact(server, project):
    section = project.find_artifacts(kind="section", limit=50)[0]
    payload = call(
        server,
        "aether_find_artifacts",
        {"addr": hex(section.addr_start), "kind": "section"},
    )["structuredContent"]
    assert payload["artifacts"]


def test_describe_schema_documents_evidence_requirements(server):
    payload = call(
        server, "aether_describe_schema", {"predicate": "contains_hardcoded_secret"}
    )["structuredContent"]
    assert payload["requires_evidence"][0]["kinds"] == ["string", "byte_span", "file"]
    fields = {f["name"] for f in payload["fields"]}
    assert fields == {"secret_kind", "detector", "redacted_preview"}


def test_neighbors_walks_from_a_claim(server):
    found = call(server, "aether_find_claims", {"limit": 1})["structuredContent"]
    claim_id = found["claims"][0]["claim_id"]
    graph = call(server, "aether_neighbors", {"node_id": claim_id, "depth": 2})[
        "structuredContent"
    ]
    assert graph["nodes"]
    assert graph["edges"]


def test_decompilation_absent_gives_an_actionable_hint(server):
    payload = call(server, "aether_get_decompilation", {"function": "main"})[
        "structuredContent"
    ]
    assert payload["returned"] == 0
    assert "ghidra" in payload["hint"].lower()


def test_unknown_object_reference_is_a_tool_error_not_a_crash(server):
    result = call(server, "aether_get_object", {"object": "no-such-file"})
    assert result["isError"] is True
    assert "no file in this project" in result["content"][0]["text"]


def test_unknown_tool_lists_the_available_ones(server):
    result = call(server, "aether_do_my_job")
    assert result["isError"] is True
    assert "aether_find_claims" in result["content"][0]["text"]


# -- write tools ------------------------------------------------------------


def test_an_agent_can_record_a_structured_claim(server, project):
    string = project.find_artifacts(kind="string", limit=1)[0]
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "contains_string",
            "statement": {"text": string.data["text"], "encoding": "ascii"},
            "evidence": [{"artifact_id": string.artifact_id, "role": "locus"}],
            "confidence": 0.8,
            "producer": "agent:test",
        },
    )["structuredContent"]

    stored = project.get_claim(result["claim_id"])
    assert stored["status"] == "proposed"
    assert stored["attestations"][0]["producer_kind"] == "agent"
    assert stored["attestations"][0]["producer"] == "agent:test"


def test_an_agent_cannot_submit_prose(server, project):
    """The headline invariant, exercised through the interface agents use."""
    string = project.find_artifacts(kind="string", limit=1)[0]
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "contains_hardcoded_secret",
            "statement": {
                "secret_kind": "api_token",
                "detector": "agent:test",
                "note": "I am fairly confident this is exploitable",
            },
            "evidence": [{"artifact_id": string.artifact_id}],
            "producer": "agent:test",
        },
    )
    assert result["isError"] is True
    assert "undeclared field(s): ['note']" in result["content"][0]["text"]
    assert not project.find_claims(producer="agent:test")


def test_an_agent_cannot_submit_a_claim_without_evidence(server, project):
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "contains_hardcoded_secret",
            "statement": {"secret_kind": "api_token", "detector": "agent:test"},
            "evidence": [],
            "producer": "agent:test",
        },
    )
    assert result["isError"] is True
    assert "needs evidence" in result["content"][0]["text"]


def test_an_agent_cannot_invent_artifact_ids(server, project):
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "contains_hardcoded_secret",
            "statement": {"secret_kind": "api_token", "detector": "agent:test"},
            "evidence": [{"artifact_id": "art_" + "0" * 32}],
            "producer": "agent:test",
        },
    )
    assert result["isError"] is True
    assert "not present in the project" in result["content"][0]["text"]


def test_an_agent_cannot_cite_the_wrong_kind_of_evidence(server, project):
    section = project.find_artifacts(kind="section", limit=1)[0]
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "contains_hardcoded_secret",
            "statement": {"secret_kind": "api_token", "detector": "agent:test"},
            "evidence": [{"artifact_id": section.artifact_id}],
            "producer": "agent:test",
        },
    )
    assert result["isError"] is True
    assert "accepts" in result["content"][0]["text"]


def test_an_agent_cannot_use_an_unregistered_predicate(server, project):
    string = project.find_artifacts(kind="string", limit=1)[0]
    result = call(
        server,
        "aether_submit_claim",
        {
            "predicate": "is_probably_backdoored",
            "statement": {},
            "evidence": [{"artifact_id": string.artifact_id}],
            "producer": "agent:test",
        },
    )
    assert result["isError"] is True
    assert "known predicates" in result["content"][0]["text"]


def test_annotations_are_the_sanctioned_place_for_prose(server, project):
    obj = project.objects()[0]
    result = call(
        server,
        "aether_annotate",
        {
            "body": "Reviewed manually: the AWS key is a documented AWS example value.",
            "target_kind": "artifact",
            "target_id": obj.artifact_id,
            "author": "agent:test",
        },
    )["structuredContent"]
    assert result["annotation_id"].startswith("ann_")
    assert project.annotations(obj.artifact_id)


def test_read_only_servers_hide_and_refuse_write_tools(project, elf_sample):
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    readonly = MCPServer(project, read_only=True)

    names = {t["name"] for t in request(readonly, "tools/list")["result"]["tools"]}
    assert "aether_submit_claim" not in names
    assert "aether_find_claims" in names

    result = call(readonly, "aether_submit_claim", {"predicate": "x", "statement": {},
                                                    "evidence": [{"artifact_id": "a"}]})
    assert result["isError"] is True
    assert "read-only" in result["content"][0]["text"]
