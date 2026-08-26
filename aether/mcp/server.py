"""MCP server over stdio, speaking JSON-RPC 2.0 with no third-party runtime.

Aether is local-first and its CLI has zero runtime dependencies; making the MCP
server the one component that drags in an async framework and a web stack would
undercut that. The protocol surface Aether needs - initialize, tools/list,
tools/call, ping - is small and stable, so it is implemented directly here.

The transport is deliberately isolated from the tool layer in
:mod:`aether.mcp.tools`. Swapping this file for the official SDK later means
reimplementing framing and nothing else; every tool, schema, and handler stays
exactly as it is. :func:`handle_message` is a pure function of request to
response, which is also what makes the protocol testable without a subprocess.
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any, BinaryIO

from aether.errors import AetherError, EvidenceError, SchemaError
from aether.project.store import Project
from aether.mcp import tools
from aether.version import AETHER_VERSION

#: MCP revision this server implements.
PROTOCOL_VERSION = "2025-06-18"

#: Versions accepted from a client. Anything else still gets a response, with
#: our version, and the client decides whether to proceed.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SERVER_NAME = "aether"

# JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class MCPServer:
    """Protocol handling for one project."""

    def __init__(self, project: Project, *, read_only: bool = False) -> None:
        self.project = project
        self.read_only = read_only
        self.initialized = False

    # -- message handling -------------------------------------------------

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message; ``None`` means no reply is owed."""
        if message.get("jsonrpc") != "2.0":
            return _error(message.get("id"), INVALID_REQUEST, "expected jsonrpc 2.0")

        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params") or {}

        if method is None:
            # A response, not a request. Nothing here initiates calls.
            return None
        if message_id is None:
            self._handle_notification(str(method))
            return None

        try:
            if method == "initialize":
                return _result(message_id, self._initialize(params))
            if method == "ping":
                return _result(message_id, {})
            if method == "tools/list":
                return _result(
                    message_id, {"tools": tools.list_tools(read_only=self.read_only)}
                )
            if method == "tools/call":
                return _result(message_id, self._call_tool(params))
            if method in ("resources/list", "resources/templates/list"):
                # Aether exposes everything through tools; answering these
                # keeps clients that probe for capabilities from erroring.
                return _result(message_id, {"resources": [], "resourceTemplates": []})
            if method == "prompts/list":
                return _result(message_id, {"prompts": []})
            return _error(
                message_id, METHOD_NOT_FOUND, f"method not supported: {method}"
            )
        except (SchemaError, EvidenceError) as exc:
            # Validation failures are the interesting case: an agent tried to
            # write something the evidence model forbids. Report them as tool
            # errors with the full message so the agent can correct itself.
            return _result(message_id, _tool_error(str(exc)))
        except AetherError as exc:
            return _result(message_id, _tool_error(str(exc)))
        except Exception as exc:  # noqa: BLE001 - never take the transport down
            return _error(
                message_id,
                INTERNAL_ERROR,
                f"{type(exc).__name__}: {exc}",
                data={"traceback": traceback.format_exc(limit=6)},
            )

    def _handle_notification(self, method: str) -> None:
        if method == "notifications/initialized":
            self.initialized = True

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or PROTOCOL_VERSION)
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        info = self.project.info()
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": AETHER_VERSION},
            "instructions": (
                f"Aether evidence graph for project '{info['name']}'. "
                "Start with aether_project_info, then aether_list_objects. "
                "Every finding is a claim backed by artifact ids: use "
                "aether_find_claims to read them and aether_get_claim to see "
                "what each one rests on. If you conclude something yourself, "
                "record it with aether_submit_claim - read "
                "aether_describe_schema first, because statements must match a "
                "registered predicate and cite real artifacts. Free-text "
                "findings are rejected by design; use aether_annotate for "
                "commentary."
            ),
        }

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not name:
            raise EvidenceError("tools/call requires a tool name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise EvidenceError("tool arguments must be an object")

        payload = tools.call_tool(
            self.project, str(name), arguments, read_only=self.read_only
        )
        text = json.dumps(payload, indent=2, sort_keys=True, default=str)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": False,
        }

    # -- transport --------------------------------------------------------

    def serve(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
        """Read newline-delimited JSON-RPC from stdin until EOF."""
        source = stdin or sys.stdin.buffer
        sink = stdout or sys.stdout.buffer

        for raw in source:
            line = raw.strip()
            if not line:
                continue
            try:
                message = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                _write(sink, _error(None, PARSE_ERROR, f"invalid JSON: {exc}"))
                continue

            if isinstance(message, list):
                # Batches are legal JSON-RPC; handle each and reply in order.
                responses = [
                    response
                    for item in message
                    if isinstance(item, dict)
                    for response in [self.handle_message(item)]
                    if response is not None
                ]
                for response in responses:
                    _write(sink, response)
                continue
            if not isinstance(message, dict):
                _write(sink, _error(None, INVALID_REQUEST, "expected an object"))
                continue

            response = self.handle_message(message)
            if response is not None:
                _write(sink, response)
        return 0


def _write(sink: BinaryIO, payload: dict[str, Any]) -> None:
    sink.write(json.dumps(payload, default=str).encode("utf-8"))
    sink.write(b"\n")
    sink.flush()


def _result(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _error(
    message_id: Any, code: int, message: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def _tool_error(message: str) -> dict[str, Any]:
    """A failed tool call.

    Returned as a successful JSON-RPC response carrying ``isError``, which is
    what the MCP spec asks for: the call reached the tool, and the tool's answer
    is that the request was invalid. An agent can read that and retry; a
    transport-level error would just look like the server broke.
    """
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def serve_project(project_root: str, *, read_only: bool = False) -> int:
    """Entry point used by ``aether mcp``."""
    project = Project.open(project_root, read_only=read_only)
    try:
        return MCPServer(project, read_only=read_only).serve()
    finally:
        project.close()


__all__ = ["MCPServer", "PROTOCOL_VERSION", "serve_project"]
