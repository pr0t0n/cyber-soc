"""Servidor MCP do motor de regras: expõe a busca RAG sobre o catálogo
unificado de skills (técnicas MITRE ATT&CK fundidas com Suricata/ModSecurity/
Sigma reais, mais D3FEND/Agent Threat Rules/correlação interna — ver
`app/services/skills_catalog.py`) como uma tool MCP por grupo, consumida pelo
Supervisor LangGraph (`app/agents/graph.py`) via stdio.

Roda como subprocesso próprio (`python -m app.mcp_server`), com sua própria
engine/sessão — não compartilha o pool de conexões do processo da API.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .config import settings
from .services.rag import search_skills_multi

mcp = FastMCP("cyber-soc-skills")

# `idle_in_transaction_session_timeout`/`statement_timeout` — mesma rede de
# segurança do engine principal (app/db.py): nenhuma transação prende uma
# conexão para sempre, seja qual for a causa. Duplicado aqui (em vez de
# importar app.db) para não instanciar o engine principal — não usado,
# desperdiçado — dentro deste subprocesso.
_connect_args = {"server_settings": {"idle_in_transaction_session_timeout": "30000", "statement_timeout": "60000"}}
_engine = create_async_engine(
    settings.database_url, pool_pre_ping=True,
    connect_args=_connect_args if settings.database_url.startswith("postgresql") else {},
)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


@mcp.tool()
async def search_attack_defend(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) técnicas MITRE ATT&CK, contramedidas MITRE
    D3FEND, regras de ameaça a agentes de IA (Agent Threat Rules — TTPs
    contra agentes, referenciam MITRE ATLAS) e regras de correlação internas
    (reputação de IP + volume/evidência) relevantes para o evento."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["attack_defend"], limit)


@mcp.tool()
async def search_network_signatures(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) técnicas MITRE ATT&CK enriquecidas com as
    assinaturas de rede reais (Suricata/Emerging Threats, regras Sigma) que as
    evidenciam, mais regras de correlação internas, relevantes para o
    tráfego/evento descrito."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["network_signature"], limit)


@mcp.tool()
async def search_web_application_rules(query: str, limit: int = 5) -> list[dict]:
    """Busca por similaridade (RAG) técnicas MITRE ATT&CK enriquecidas com as
    regras de WAF reais (ModSecurity/OWASP CRS) que as evidenciam, mais
    regras de correlação internas, relevantes para o payload/comportamento
    descrito."""
    async with _session_factory() as db:
        return await search_skills_multi(db, query, ["web_application"], limit)


if __name__ == "__main__":
    mcp.run(transport="stdio")
