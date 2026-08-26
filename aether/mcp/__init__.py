"""MCP server exposing the evidence graph to agents and MCP-aware clients."""

from aether.mcp.server import MCPServer, PROTOCOL_VERSION, serve_project

__all__ = ["MCPServer", "PROTOCOL_VERSION", "serve_project"]
