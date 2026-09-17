"""Servidor MCP do motor de regras: expõe a busca RAG sobre o catálogo real de
skills (ATT&CK/D3FEND/Suricata/ModSecurity/Sigma/Agent Threat Rules) como uma
tool MCP, consumida pelos grupos do Supervisor LangGraph (`app/agents/graph.py`)
via stdio.

Roda como subprocesso próprio (`python -m app.mcp_server`), com sua própria
engine/sessão — não compartilha o pool de conexões do processo da API.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .config import settings
from .services.rag import search_skills_multi

mcp = FastMCP("cyber-soc-skills")

_engine = create_async_engine(settings.database_url, pool_pre_ping=True)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


@mcp.tool()
async def search_attack_defend(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) técnicas MITRE ATT&CK, contramedidas MITRE
    D3FEND, regras de ameaça a agentes de IA (Agent Threat Rules — TTPs
    contra agentes, referenciam MITRE ATLAS) e regras de correlação internas
    (reputação de IP + volume/evidência) relevantes para o evento."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["attack", "d3fend", "agent_threats", "correlation"], limit)


@mcp.tool()
async def search_network_signatures(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) assinaturas de rede Suricata/Emerging
    Threats, regras de detecção Sigma (SigmaHQ + SIEM-Content) e regras de
    correlação internas relevantes para o tráfego/evento descrito."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["suricata", "sigma", "correlation"], limit)


@mcp.tool()
async def search_web_application_rules(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) regras de WAF ModSecurity/OWASP CRS e
    regras de correlação internas relevantes para o payload/comportamento
    descrito."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["modsecurity", "correlation"], limit)


if __name__ == "__main__":
    mcp.run(transport="stdio")
