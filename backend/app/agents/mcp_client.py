"""Cliente MCP persistente do processo da API — conecta ao servidor MCP de
skills (`app/mcp_server.py`) via stdio (subprocesso) e expõe as tools de RAG
para os grupos do Supervisor LangGraph.

Mantém UMA sessão MCP viva pelo processo inteiro, não uma por chamada.
`MultiServerMCPClient.get_tools()` (usado antes) devolve tools cuja própria
biblioteca documenta: "a new session will be created for each tool call" —
ou seja, CADA busca RAG (search_attack_defend/search_network_signatures/
search_web_application_rules) reabria um subprocesso `python -m
app.mcp_server` inteiro do zero (fork/exec + importar toda a stack FastMCP/
SQLAlchemy/mcp SDK + abrir um engine/pool Postgres novo), só pra fechar de
novo ao fim daquela ÚNICA chamada.

Achado real de teste de carga: sob a concorrência necessária pra absorver
uma rajada de ingestão, o custo de spawn repetido saturou CPU/memória/
conexões o bastante para travar o event loop inteiro do processo da API
(observado: as 50 conexões do pool ficaram "idle in transaction" por
minutos, health check parou de responder). Uma sessão só, reaproveitada,
elimina esse custo — o protocolo MCP já suporta várias chamadas concorrentes
multiplexadas na mesma sessão (por id de requisição), então não há perda de
paralelismo real.

A sessão (e o task group `anyio` que o transporte stdio usa por baixo) só
pode ser aberta e fechada pela MESMA task (`anyio` reforça isso — concorrência
estruturada). Por isso o ciclo de vida mora numa task dedicada
(`_session_owner`, criada uma vez e mantida viva até o shutdown) em vez de
`__aenter__`/`__aexit__` chamados de tasks diferentes (o que já quebrou aqui
com `RuntimeError: Attempted to exit cancel scope in a different task than
it was entered in`). Outras tasks só leem `_tools` (dict de BaseTool já
vinculado à sessão) e chamam `.ainvoke(...)` normalmente — isso opera sobre
streams internas seguras entre tasks, não sobre o cancel scope em si."""
from __future__ import annotations

import asyncio
import os
import sys

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools

_tools: dict[str, BaseTool] | None = None
_owner_task: asyncio.Task | None = None
_ready = asyncio.Event()
_shutdown = asyncio.Event()

# Achado real de teste de carga: cheguei a serializar `.ainvoke()` por um
# `asyncio.Lock()` global aqui, como mitigação conservadora contra uma
# suspeita (nunca confirmada) de que chamadas concorrentes sobre a sessão
# persistente não fossem seguras. Isso trocou um problema por outro pior: um
# `asyncio.Lock` puro não tem timeout — se UM holder travar por qualquer
# motivo (subprocesso MCP, embedding no Ollama sob contenção de CPU), TODAS
# as buscas RAG do processo inteiro ficam paradas atrás dele pra sempre, sem
# nenhuma via de recuperação (nem o timeout de 30s do `asyncio.wait_for` em
# volta da chamada ajuda — ele só cancela a ESPERA da RESPOSTA depois que o
# lock já foi adquirido; não afeta quem ainda está esperando o lock em si).
# O protocolo MCP já documenta suporte real a chamadas concorrentes
# multiplexadas por id de requisição (`mcp.shared.session.BaseSession.
# send_request`, verificado na fonte) — não precisa de lock nenhum aqui; o
# gargalo de verdade já é o Ollama (`_ANALYSIS_CONCURRENCY`, rules_engine.py).


def _build_client() -> MultiServerMCPClient:
    return MultiServerMCPClient({
        "skills": {
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-m", "app.mcp_server"],
            # O SDK `mcp` (stdio_client) NÃO herda o ambiente do processo pai
            # por padrão — só repassa uma lista mínima de variáveis
            # "seguras" (PATH/HOME/... , ver mcp.client.stdio.
            # get_default_environment). Sem isso, o subprocesso nunca via
            # DATABASE_URL/LLM_BASE_URL (settings.py cai no default
            # hardcoded "localhost", que não existe dentro do container) —
            # achado real: toda busca RAG falhava silenciosamente (erro de
            # conexão Postgres virava "1 candidata" de texto de erro, nunca
            # uma exceção que os grupos tratassem como degraded) desde o
            # primeiro cold start do subprocesso MCP.
            "env": dict(os.environ),
        }
    })


async def _session_owner() -> None:
    """Dona da sessão MCP pela vida inteira do processo — abre, publica as
    tools, espera o sinal de shutdown, fecha. Nunca sai antes disso (é o que
    respeita a regra do `anyio` de abrir/fechar o task group na mesma task)."""
    global _tools
    client = _build_client()
    async with client.session("skills") as session:
        tools = await load_mcp_tools(session)
        _tools = {t.name: t for t in tools}
        _ready.set()
        await _shutdown.wait()
    _tools = None


async def get_skill_tools() -> dict[str, BaseTool]:
    global _owner_task
    if _owner_task is None:
        _owner_task = asyncio.create_task(_session_owner())
    await _ready.wait()
    assert _tools is not None
    return _tools


async def close_skill_tools() -> None:
    """Encerra a sessão/subprocesso MCP — chamado no shutdown do processo
    (app/main.py lifespan), nunca deixa o subprocesso órfão rodando."""
    global _owner_task
    if _owner_task is None:
        return
    _shutdown.set()
    await _owner_task
    _owner_task = None
    _ready.clear()
    _shutdown.clear()
