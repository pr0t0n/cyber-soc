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
from typing import Any, Awaitable, Callable, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from ..config import settings
from ..services.correlation import CORRELATION_WINDOW_MINUTES
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
    # True quando o veredito não vem de um julgamento completo (RAG/MCP fora
    # do ar, ou a IA não respondeu/não respondeu em JSON) — só é confiável se
    # `matched` tiver vindo de uma correspondência exata determinística
    # (ver _exact_id_matches). Existe para o Supervisor nunca relatar um
    # "não corresponde" degradado com o mesmo tom de confiança de um
    # "não corresponde" real, avaliado de ponta a ponta.
    degraded: bool
    # True quando `matched` veio de _exact_id_matches (fato objetivo: a fonte
    # já reportou essa técnica e o catálogo tem a skill), não de uma inferência
    # do LLM — nesse caso nem o grupo nem o Supervisor precisam gastar uma
    # chamada de LLM (segundos a minutos em CPU) para "confirmar" o óbvio. É a
    # diferença entre um SOC de verdade (toca o óbvio na hora, investiga só o
    # que é ambíguo) e tratar todo evento com o mesmo processo lento.
    deterministic: bool


OnProgress = Callable[[str, GroupVerdict], Awaitable[None]]


class RulesEngineState(TypedDict):
    event: dict[str, Any]
    event_summary: str
    attack_defend: GroupVerdict
    network_signature: GroupVerdict
    web_application: GroupVerdict
    verdict: dict[str, Any]
    on_progress: OnProgress | None


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
    parts = [
        f"{event.get('type', '')} severidade={event.get('severity')} "
        f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
        f"{event.get('dst_ip', '?')}:{event.get('dst_port', '?')} / {event.get('protocol', '?')} "
        f"mitre={','.join(event.get('mitre') or [])} comportamento={event.get('behavior') or ''}"
    ]
    if event.get("hit_count") is not None:
        parts.append(f"tentativas/repetições relatadas pela fonte={event['hit_count']}")
    else:
        parts.append("tentativas/repetições relatadas pela fonte=não informado")
    if event.get("rule_ref"):
        parts.append(f"regra de origem={event['rule_ref']}")
    correlated = event.get("correlated_count")
    if correlated and correlated > 1:
        parts.append(
            f"correlação: esta mesma origem gerou {correlated} evento(s) nos últimos "
            f"{CORRELATION_WINDOW_MINUTES} minutos (não é um evento isolado)"
        )
    reasons = ((event.get("enrichment") or {}).get("assessment") or {}).get("reasons") or []
    if reasons:
        parts.append("threat intel do IP de origem: " + " ".join(reasons))
    return " ".join(p.strip() for p in parts if p).strip()


_MCP_TIMEOUT_SECONDS = 30.0
# Mesma ordem de grandeza do timeout do Copilot (LLM_TIMEOUT_SECONDS) — Ollama
# em CPU compartilhado pode legitimamente demorar; sem isso, uma chamada
# travada (observado: nem chega a logar a requisição HTTP) prende o evento em
# "pending" para sempre, já que `ainvoke` nunca retorna.
_LLM_CALL_TIMEOUT_SECONDS = 120.0
# Teto absoluto do grafo inteiro (4 chamadas de LLM em sequência, cada uma já
# com retry) — garante que um evento nunca fique "pending" para sempre.
_TOTAL_TIMEOUT_SECONDS = 900.0


def _exact_id_matches(event: dict[str, Any], candidates: list[dict]) -> list[dict]:
    """Correspondência exata e determinística entre a técnica MITRE já
    reportada pela fonte (`event.mitre`, ex.: T1110) e o `external_id` de uma
    skill candidata (ex.: técnica ATT&CK T1110 "Brute Force"). Isso não
    depende do julgamento do LLM (qwen2.5:1.5b — pequeno, ocasionalmente
    inconsistente sob contenção de CPU): se a própria fonte já identificou a
    técnica e o catálogo tem a skill com o mesmo ID, é uma correspondência
    objetiva, não uma opinião da IA."""
    mitre_ids = set(event.get("mitre") or [])
    if not mitre_ids:
        return []
    return [c for c in candidates if c.get("external_id") in mitre_ids]


async def _run_group(state: RulesEngineState, tool_name: str, system_prompt: str) -> GroupVerdict:
    try:
        tools = await asyncio.wait_for(get_skill_tools(), timeout=_MCP_TIMEOUT_SECONDS)
        candidates = await asyncio.wait_for(
            tools[tool_name].ainvoke({"query": state["event_summary"], "limit": 5}), timeout=_MCP_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 — MCP/RAG travado ou fora do ar não derruba os outros grupos
        return {
            "matched": False, "skills": [], "reasoning": f"RAG indisponível: {exc}"[:200],
            "candidates_considered": 0, "degraded": True,
        }

    if not candidates:
        return {
            "matched": False, "skills": [], "reasoning": "Sem skills candidatas retornadas pelo RAG.",
            "candidates_considered": 0, "degraded": True, "deterministic": False,
        }

    forced = _exact_id_matches(state["event"], candidates)
    forced_ids = [c["external_id"] for c in forced]
    forced_names = [c["name"] for c in forced]

    if forced:
        # Correspondência objetiva (fato, não opinião) — não gasta uma chamada
        # de LLM (a parte lenta) para "confirmar" o que já é certo. Um SOC de
        # verdade também bate o óbvio na hora.
        return {
            "matched": True, "skills": forced_ids,
            "reasoning": f"Correspondência exata de técnica já reportada pela fonte com o catálogo: {forced_names}.",
            "candidates_considered": len(candidates), "degraded": False, "deterministic": True,
        }

    prompt = (
        f"Evento:\n{state['event_summary']}\n\n"
        f"Skills candidatas (RAG):\n{json.dumps(candidates, ensure_ascii=False, indent=1)}"
    )
    content = await _invoke_llm_with_retry(system_prompt, prompt)
    if content is None:
        return {
            "matched": False, "skills": [], "reasoning": "IA indisponível para este grupo.",
            "candidates_considered": len(candidates), "degraded": True, "deterministic": False,
        }
    parsed = _parse_json(content)
    if not parsed:
        return {
            "matched": False, "skills": [], "reasoning": "IA não respondeu em JSON válido.",
            "candidates_considered": len(candidates), "degraded": True, "deterministic": False,
        }
    return {
        "matched": bool(parsed.get("matched")),
        "skills": list(parsed.get("skills") or []),
        "reasoning": str(parsed.get("reasoning") or ""),
        "candidates_considered": len(candidates),
        "degraded": False,
        "deterministic": False,
    }


async def _notify(state: RulesEngineState, stage: str, verdict: GroupVerdict) -> None:
    """Reporta o veredito do grupo assim que ele termina — é o que permite a UI
    mostrar o agente 'trabalhando' em tempo real, em vez de um status parado em
    'pending' até o grafo inteiro (até ~900s no pior caso) terminar."""
    cb = state.get("on_progress")
    if cb is None:
        return
    try:
        await cb(stage, verdict)
    except Exception:  # noqa: BLE001 — nunca deixa o progresso derrubar a análise
        pass


async def attack_defend_node(state: RulesEngineState) -> dict:
    verdict = await _run_group(state, "search_attack_defend", ATTACK_DEFEND_GROUP_PROMPT)
    await _notify(state, "attack_defend", verdict)
    return {"attack_defend": verdict}


async def network_signature_node(state: RulesEngineState) -> dict:
    verdict = await _run_group(state, "search_network_signatures", NETWORK_SIGNATURE_GROUP_PROMPT)
    await _notify(state, "network_signature", verdict)
    return {"network_signature": verdict}


async def web_application_node(state: RulesEngineState) -> dict:
    verdict = await _run_group(state, "search_web_application_rules", WEB_APPLICATION_GROUP_PROMPT)
    await _notify(state, "web_application", verdict)
    return {"web_application": verdict}


def _deterministic_consolidation(groups: dict[str, GroupVerdict], *, reason: str) -> dict:
    """OR determinístico dos 3 grupos — nunca perde um match real que algum
    grupo já tinha encontrado. Usado tanto quando o Supervisor (LLM) não
    responde (fallback reativo) quanto, no caminho rápido, quando já não há
    nada de fato para o LLM decidir (fast path proativo)."""
    all_skills = groups["attack_defend"]["skills"] + groups["network_signature"]["skills"] + groups["web_application"]["skills"]
    matched = any(g["matched"] for g in groups.values())
    any_degraded = any(g["degraded"] for g in groups.values())
    if matched:
        recommendation = "Revisar manualmente — skill(s) casada(s) mas o Supervisor (IA) não consolidou o resumo."
    elif any_degraded:
        # Distinção importante: isto NÃO é "analisado e não encontrado" —
        # pelo menos um grupo não completou uma avaliação real (RAG ou IA
        # indisponível), então "sem skill correspondente" seria uma
        # afirmação mais forte do que a evidência sustenta.
        recommendation = (
            "Inconclusivo — revisar manualmente. Um ou mais grupos do motor de regras não "
            "completaram a análise (RAG ou IA indisponível no momento), então a ausência de "
            "correspondência aqui não é definitiva."
        )
    else:
        recommendation = "Nenhuma ação necessária — sem skill correspondente."
    return {
        "matched": matched, "matched_skills": all_skills,
        "summary": f"Consolidação determinística ({reason}).",
        "recommendation": recommendation, "groups": groups,
    }


async def supervisor_node(state: RulesEngineState) -> dict:
    # Mesmas chaves usadas por _persist_progress/_notify (nome do nó, não um
    # rótulo em português) — o veredito final (aqui) e o progresso incremental
    # (rules_engine.py) escrevem no mesmo `rules_engine_verdict.groups`, e a UI
    # (Eventos) só reconhece a trilha do agente se as chaves forem idênticas.
    groups = {
        "attack_defend": state["attack_defend"],
        "network_signature": state["network_signature"],
        "web_application": state["web_application"],
    }

    if any(g["deterministic"] for g in groups.values()):
        # Fast path proativo: pelo menos um grupo já confirmou por fato
        # objetivo (técnica reportada pela fonte bate com o catálogo) — pedir
        # ao Supervisor (LLM) para "opinar" sobre algo já certo só adiciona
        # minutos de latência de CPU sem agregar confiança nenhuma.
        return {"verdict": _deterministic_consolidation(groups, reason="técnica confirmada pela fonte, sem chamada de IA")}

    prompt = f"Evento:\n{state['event_summary']}\n\nVeredito dos grupos:\n{json.dumps(groups, ensure_ascii=False, indent=1)}"
    content = await _invoke_llm_with_retry(SUPERVISOR_PROMPT, prompt)
    parsed = _parse_json(content) if content else None
    if not parsed:
        # Sem o Supervisor conseguir consolidar (IA indisponível ou resposta
        # não é JSON), cai para o OR determinístico dos grupos (fallback
        # reativo, distinto do fast path acima).
        any_degraded = any(g["degraded"] for g in groups.values())
        reason = "IA não respondeu em JSON válido" + (" — análise parcialmente degradada" if any_degraded else "")
        return {"verdict": _deterministic_consolidation(groups, reason=reason)}
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


async def analyze_event(event: dict[str, Any], on_progress: OnProgress | None = None) -> dict:
    """Ponto de entrada do motor de regras — chamado em background após a
    ingestão (app/api/ingest.py). Nunca levanta: falha de IA vira veredito
    'não casou' explicado, não exceção que perderia o evento.

    `on_progress(stage, group_verdict)` é chamado assim que cada grupo termina
    (attack_defend/network_signature/web_application) — permite persistir o
    andamento no evento em tempo real, em vez de só no fim do grafo."""
    state: RulesEngineState = {
        "event": event,
        "event_summary": _event_summary(event),
        "attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": False, "deterministic": False},
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": False, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": False, "deterministic": False},
        "verdict": {},
        "on_progress": on_progress,
    }
    try:
        result = await asyncio.wait_for(_get_graph().ainvoke(state), timeout=_TOTAL_TIMEOUT_SECONDS)
        return result["verdict"]
    except Exception as exc:  # noqa: BLE001 — motor de regras nunca derruba a ingestão nem trava "pending" para sempre
        return {
            "matched": False, "matched_skills": [], "summary": f"Motor de regras indisponível: {exc}"[:300],
            "recommendation": "Análise automática indisponível — revisar o evento manualmente.", "groups": {},
        }
