# -*- coding: utf-8 -*-
"""MCP (Model Context Protocol) tool-server client integration.

Opt-in bridge so Decepticon agents can use tools exposed by external
MCP servers (e.g. Kali MCP server, HexStrike). Activation is purely
env-driven (``DECEPTICON_MCP__SERVERS``) and requires the optional
``langchain-mcp-adapters`` package to be installed separately —
nothing in this subpackage is imported at framework start-up.

See ``docs/mcp.md`` for operator-facing configuration notes.
"""

from __future__ import annotations

from decepticon.tools.mcp.client import (
    MCPServerConfig,
    load_mcp_tools,
    mcp_servers_configured,
    parse_mcp_servers_env,
)

__all__ = [
    "MCPServerConfig",
    "load_mcp_tools",
    "mcp_servers_configured",
    "parse_mcp_servers_env",
]
