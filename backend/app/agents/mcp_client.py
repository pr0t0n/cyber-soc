"""Cliente MCP persistente do processo da API — conecta ao servidor MCP de
skills (`app/mcp_server.py`) via stdio (subprocesso) e expõe as tools de RAG
para os grupos do Supervisor LangGraph."""
from __future__ import annotations

import sys

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient

_client: MultiServerMCPClient | None = None
_tools: dict[str, BaseTool] | None = None


def _build_client() -> MultiServerMCPClient:
    return MultiServerMCPClient({
        "skills": {
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-m", "app.mcp_server"],
        }
    })


async def get_skill_tools() -> dict[str, BaseTool]:
    global _client, _tools
    if _tools is None:
        _client = _build_client()
        tools = await _client.get_tools()
        _tools = {t.name: t for t in tools}
    return _tools
