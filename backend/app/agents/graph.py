"""Motor de regras: Supervisor LangGraph sobre 3 grupos especialistas, cada um
hidratado por RAG (via MCP) sobre o catálogo real de skills.

    START --> attack_defend_group --> network_signature_group
          --> web_application_group --> supervisor --> END

Encadeado (não fan-out paralelo) de propósito: todos os grupos e o Supervisor
compartilham o mesmo Ollama local (CPU, um único worker de inferência) —
disparar as 3 chamadas ao mesmo tempo só cria contenção, e em produção já
derrubou o `llama-server` por memória. Cada nó continua um agente
independente, com seu próprio prompt e tool MCP; só a orquestração é
sequencial. Falha de um grupo (Ollama indisponível/derrubado) não aborta o
grafo — vira um veredito "não casou" só daquele grupo, com retry automático.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from ..config import settings
from .mcp_client import get_skill_tools
from .prompts import (
    ATTACK_DEFEND_GROUP_PROMPT,
    NETWORK_SIGNATURE_GROUP_PROMPT,
    SUPERVISOR_PROMPT,
    WEB_APPLICATION_GROUP_PROMPT,
)


class GroupVerdict(TypedDict):
    matched: bool
    skills: list[str]
    reasoning: str
    candidates_considered: int


class RulesEngineState(TypedDict):
    event: dict[str, Any]
    event_summary: str
    attack_defend: GroupVerdict
    network_signature: GroupVerdict
    web_application: GroupVerdict
    verdict: dict[str, Any]


def _llm() -> ChatOllama:
    return ChatOllama(base_url=settings.llm_base_url.removesuffix("/v1"), model=settings.llm_model, temperature=0.1)


async def _invoke_llm_with_retry(system_prompt: str, prompt: str, attempts: int = 2) -> str | None:
    """Ollama local (CPU, memória compartilhada com outros processos do host)
    ocasionalmente derruba a inferência (`llama-server` morto por OOM) sob
    contenção — uma nova tentativa quase sempre se recupera, porque o Ollama
    já reinicia o `llama-server` sozinho na próxima requisição."""
    for attempt in range(attempts):
        try:
            response = await asyncio.wait_for(
                _llm().ainvoke([SystemMessage(system_prompt), HumanMessage(prompt)]),
                timeout=_LLM_CALL_TIMEOUT_SECONDS,
            )
            return str(response.content)
        except Exception:  # noqa: BLE001 — Ollama indisponível/travado/derrubado; tenta de novo ou degrada
            if attempt + 1 < attempts:
                await asyncio.sleep(3)
    return None


def _parse_json(content: str) -> dict | None:
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _event_summary(event: dict[str, Any]) -> str:
    return (
        f"{event.get('type', '')} severidade={event.get('severity')} "
        f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
        f"{event.get('dst_ip', '?')}:{event.get('dst_port', '?')} / {event.get('protocol', '?')} "
        f"mitre={','.join(event.get('mitre') or [])} comportamento={event.get('behavior') or ''}"
    ).strip()


_MCP_TIMEOUT_SECONDS = 30.0
# Mesma ordem de grandeza do timeout do Copilot (LLM_TIMEOUT_SECONDS) — Ollama
# em CPU compartilhado pode legitimamente demorar; sem isso, uma chamada
# travada (observado: nem chega a logar a requisição HTTP) prende o evento em
# "pending" para sempre, já que `ainvoke` nunca retorna.
_LLM_CALL_TIMEOUT_SECONDS = 120.0
# Teto absoluto do grafo inteiro (4 chamadas de LLM em sequência, cada uma já
# com retry) — garante que um evento nunca fique "pending" para sempre.
_TOTAL_TIMEOUT_SECONDS = 900.0


async def _run_group(state: RulesEngineState, tool_name: str, system_prompt: str) -> GroupVerdict:
    try:
        tools = await asyncio.wait_for(get_skill_tools(), timeout=_MCP_TIMEOUT_SECONDS)
        candidates = await asyncio.wait_for(
            tools[tool_name].ainvoke({"query": state["event_summary"], "limit": 5}), timeout=_MCP_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 — MCP/RAG travado ou fora do ar não derruba os outros grupos
        return {"matched": False, "skills": [], "reasoning": f"RAG indisponível: {exc}"[:200], "candidates_considered": 0}
    if not candidates:
        return {"matched": False, "skills": [], "reasoning": "Sem skills candidatas retornadas pelo RAG.", "candidates_considered": 0}

    prompt = (
        f"Evento:\n{state['event_summary']}\n\n"
        f"Skills candidatas (RAG):\n{json.dumps(candidates, ensure_ascii=False, indent=1)}"
    )
    content = await _invoke_llm_with_retry(system_prompt, prompt)
    if content is None:
        return {"matched": False, "skills": [], "reasoning": "IA indisponível para este grupo.", "candidates_considered": len(candidates)}
    parsed = _parse_json(content)
    if not parsed:
        return {"matched": False, "skills": [], "reasoning": "IA não respondeu em JSON válido.", "candidates_considered": len(candidates)}
    return {
        "matched": bool(parsed.get("matched")),
        "skills": list(parsed.get("skills") or []),
        "reasoning": str(parsed.get("reasoning") or ""),
        "candidates_considered": len(candidates),
    }


async def attack_defend_node(state: RulesEngineState) -> dict:
    return {"attack_defend": await _run_group(state, "search_attack_defend", ATTACK_DEFEND_GROUP_PROMPT)}


async def network_signature_node(state: RulesEngineState) -> dict:
    return {"network_signature": await _run_group(state, "search_network_signatures", NETWORK_SIGNATURE_GROUP_PROMPT)}


async def web_application_node(state: RulesEngineState) -> dict:
    return {"web_application": await _run_group(state, "search_web_application_rules", WEB_APPLICATION_GROUP_PROMPT)}


async def supervisor_node(state: RulesEngineState) -> dict:
    groups = {
        "ttp_defesa": state["attack_defend"],
        "assinaturas_rede": state["network_signature"],
        "aplicacao_web": state["web_application"],
    }
    prompt = f"Evento:\n{state['event_summary']}\n\nVeredito dos grupos:\n{json.dumps(groups, ensure_ascii=False, indent=1)}"
    content = await _invoke_llm_with_retry(SUPERVISOR_PROMPT, prompt)
    parsed = _parse_json(content) if content else None
    if not parsed:
        # Sem o Supervisor conseguir consolidar (IA indisponível ou resposta
        # não é JSON), cai para o OR determinístico dos grupos — nunca perde
        # um match real que algum grupo já tinha encontrado.
        all_skills = groups["ttp_defesa"]["skills"] + groups["assinaturas_rede"]["skills"] + groups["aplicacao_web"]["skills"]
        matched = any(g["matched"] for g in groups.values())
        recommendation = (
            "Revisar manualmente — skill(s) casada(s) mas o Supervisor (IA) não consolidou o resumo."
            if matched else "Nenhuma ação necessária — sem skill correspondente."
        )
        return {"verdict": {
            "matched": matched, "matched_skills": all_skills,
            "summary": "Consolidação determinística (IA não respondeu em JSON válido).",
            "recommendation": recommendation, "groups": groups,
        }}
    return {"verdict": {
        "matched": bool(parsed.get("matched")),
        "matched_skills": list(parsed.get("matched_skills") or []),
        "summary": str(parsed.get("summary") or ""),
        "recommendation": str(parsed.get("recommendation") or ""),
        "groups": groups,
    }}


_compiled = None


def _build_graph():
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(RulesEngineState)
    graph.add_node("attack_defend_group", attack_defend_node)
    graph.add_node("network_signature_group", network_signature_node)
    graph.add_node("web_application_group", web_application_node)
    graph.add_node("supervisor", supervisor_node)

    graph.add_edge(START, "attack_defend_group")
    graph.add_edge("attack_defend_group", "network_signature_group")
    graph.add_edge("network_signature_group", "web_application_group")
    graph.add_edge("web_application_group", "supervisor")
    graph.add_edge("supervisor", END)
    return graph.compile()


def _get_graph():
    global _compiled
    if _compiled is None:
        _compiled = _build_graph()
    return _compiled


async def analyze_event(event: dict[str, Any]) -> dict:
    """Ponto de entrada do motor de regras — chamado em background após a
    ingestão (app/api/ingest.py). Nunca levanta: falha de IA vira veredito
    'não casou' explicado, não exceção que perderia o evento."""
    state: RulesEngineState = {
        "event": event,
        "event_summary": _event_summary(event),
        "attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0},
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0},
        "verdict": {},
    }
    try:
        result = await asyncio.wait_for(_get_graph().ainvoke(state), timeout=_TOTAL_TIMEOUT_SECONDS)
        return result["verdict"]
    except Exception as exc:  # noqa: BLE001 — motor de regras nunca derruba a ingestão nem trava "pending" para sempre
        return {
            "matched": False, "matched_skills": [], "summary": f"Motor de regras indisponível: {exc}"[:300],
            "recommendation": "Análise automática indisponível — revisar o evento manualmente.", "groups": {},
        }
