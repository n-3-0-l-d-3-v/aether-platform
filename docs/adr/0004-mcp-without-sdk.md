# ADR 0004: The MCP server speaks the protocol directly

**Status:** accepted · **Date:** 2026-08-26

## Context

The specification requires the "official MCP protocol (stdio or HTTP)" and calls
the MCP tools "the primary interface for future agents". The official Python
SDK (`mcp`) is available and installs cleanly.

## Decision

Implement the protocol directly over stdio JSON-RPC 2.0, in
`aether/mcp/server.py`, with no third-party runtime.

"Official protocol" is a statement about the wire format, and the wire format is
what this implements: `initialize` with version negotiation, `tools/list`,
`tools/call` returning content blocks and `structuredContent`, `ping`, and
polite empty answers for `resources/list` and `prompts/list` so clients that
probe for capabilities do not error.

## Rationale

The SDK pulls anyio, httpx, starlette, uvicorn, and pydantic-settings. Aether's
core has zero runtime dependencies, and making the MCP server the one component
that drags in a web stack would undercut that property everywhere it matters —
including inside constrained analysis environments where installing packages is
awkward.

Against that: the surface Aether needs is four methods, all stable, and the
framing is newline-delimited JSON. That is a small, well-specified thing to
implement, and the risk of drift is bounded by how rarely those four methods
change.

Two design choices contain the risk:

- **Transport is isolated from tools.** Every tool, schema, and handler lives in
  `aether/mcp/tools.py` and knows nothing about JSON-RPC. Swapping in the SDK
  later means reimplementing framing and nothing else.
- **`handle_message` is a pure function** of request to response. The protocol
  is testable in-process, with no subprocess and no event loop, which is why the
  MCP test file covers version negotiation, batches, malformed input, and
  notification handling directly.

## Error mapping

The distinction that matters for agents: a *transport* error means the server
broke, while a *tool* error means the request was invalid and the agent should
correct itself. Validation failures — a prose field, missing evidence, a made-up
artifact id — are returned as successful JSON-RPC responses carrying
`isError: true` and the full message. An agent reads the reason and retries. A
JSON-RPC error code would have looked like a server fault.

## Consequences

- `pip install aether` brings a working MCP server with nothing else.
- Protocol revisions must be tracked by hand. `SUPPORTED_PROTOCOL_VERSIONS`
  makes the accepted set explicit, and an unrecognized version is answered with
  ours rather than refused.
- HTTP transport is not implemented. Nothing in Phase 0 or Phase 1 needs it;
  adding it means one more module beside `server.py`.

## Revisit when

MCP adds a capability Aether needs that is genuinely awkward to implement by
hand — sampling, elicitation, or server-initiated notifications — or when the
tool surface stops being the only thing exposed.
