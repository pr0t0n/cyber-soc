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
from pathlib import Path
from typing import Any, Awaitable, Callable, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from ..config import settings
from ..services.correlation import CORRELATION_WINDOW_MINUTES
from ..services.mitre import describe_technique
from . import mcp_client
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


def _load_correlation_titles() -> dict[str, str]:
    """Nome real das regras de correlação internas (CSOC-00x), lido direto
    do JSON estático (não precisa de sessão de banco, ao contrário da tabela
    `skills`) — só usado para dar contexto real ao Supervisor, nunca gerado."""
    path = Path(__file__).parent.parent / "skills_data" / "correlation.json"
    items = json.loads(path.read_text())
    return {it["id"]: it["title"] for it in items}


_CORRELATION_TITLES = _load_correlation_titles()


def _describe_group_skill(skill_id: str) -> str:
    """"T1110" -> descrição real da técnica (mitre.py); "CSOC-002" -> nome
    real da regra de correlação — dá ao Supervisor (LLM) o CONTEÚDO da skill
    casada, não só o ID cru. Achado real: sem isto, a recomendação final do
    Supervisor ficava genérica ("revisar o evento") porque ele nunca sabia
    de fato o que "T1110"/"CSOC-002" significam, só via a string do ID."""
    if re.fullmatch(r"T\d{4,5}(\.\d{3})?", skill_id):
        return describe_technique(skill_id)
    if skill_id in _CORRELATION_TITLES:
        return f"{skill_id} ({_CORRELATION_TITLES[skill_id]})"
    return skill_id


def _describe_groups_for_prompt(groups: dict[str, "GroupVerdict"]) -> dict[str, dict]:
    return {
        stage: {**verdict, "skills": [_describe_group_skill(s) for s in verdict["skills"]]}
        for stage, verdict in groups.items()
    }


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
    if event.get("incident_context"):
        parts.append(str(event["incident_context"]))
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


def _unwrap_mcp_candidates(raw: list[Any]) -> list[dict]:
    """`tools[tool_name].ainvoke(...)` (langchain_mcp_adapters) devolve o
    `content` bruto do protocolo MCP, não o valor de retorno Python da tool
    já desserializado: FastMCP, para uma tool anotada `-> list[dict]`,
    serializa CADA item da lista como um content block de texto
    `{"type": "text", "text": "<json>", "id": ...}` (compatibilidade com
    clientes que só leem texto) — o `structuredContent` do protocolo (que
    teria a lista de dicts pronta) não é o que a lib de adapter expõe aqui.
    Achado real: sem desembrulhar isso, TODA candidata chegava a
    `_exact_id_matches`/ao prompt do LLM sem a chave `external_id` (só
    `type`/`text`/`id`) — a via determinística nunca disparava (silenciosamente
    sempre `[]`) e o LLM via um JSON duplamente serializado em vez da lista
    de skills candidatas de verdade."""
    out: list[dict] = []
    for item in raw:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            try:
                parsed = json.loads(item["text"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


# CSOC-001..004 (correlation.json) exigem evidência real (`requires`) —
# reputação de IP confirmada, volume, payload de ataque — verificada de
# forma determinística por `correlation_rules.evaluate()`
# (rules_engine.py), ANTES de qualquer evento chegar ao motor de IA. CSOC-005
# fica de fora de propósito: é a regra "sem corroboração real, revisão
# manual obrigatória" — o oposto de exigir evidência, correto o LLM poder
# citá-la.
_EVIDENCE_REQUIRING_CORRELATION_IDS = frozenset({"CSOC-001", "CSOC-002", "CSOC-003", "CSOC-004"})

# Achado real de teste de carga (processo de aprendizado): o LLM confirmava
# consistentemente uma Agent Threat Rule ("Encoding-Based Prompt Injection
# Evasion", sobre INSTRUÇÕES MALICIOSAS ENCODADAS ENVIADAS A UM AGENTE/LLM)
# para um evento de PowerShell ofuscado num HOST WINDOWS comum — mesmo
# "técnica de encoding para evasão" na superfície, mas categoria de ataque
# completamente diferente (nenhum agente de IA envolvido). Consistente o
# bastante pra ser promovido (a mesma alucinação repetida não é pega pela
# checagem de consistência do learning.py). Agent Threat Rules (prefixo
# "ATR-") só fazem sentido quando o evento de fato menciona um agente/LLM —
# checagem determinística de palavra-chave, não julgamento do modelo.
_AGENT_THREAT_ID_PREFIX = "ATR-"
_AGENT_CONTEXT_RE = re.compile(
    r"(?i)\bprompt\b|\bllm\b|\bagente?s?\s+de\s+ia\b|\bagent\b|\bmcp\b|model\s+context\s+protocol|"
    r"modelo\s+de\s+linguagem|\bchatbot\b|\bcopilot\b|assistente\s+de\s+ia|tool[\s_-]?call|"
    r"orquestrador\s+de\s+agentes|\bmodel\b.*\bapi\b"
)


def _has_agent_context(event: dict[str, Any]) -> bool:
    text = " ".join(str(event.get(k) or "") for k in ("type", "behavior"))
    return bool(_AGENT_CONTEXT_RE.search(text))


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
        raw_candidates = await asyncio.wait_for(
            tools[tool_name].ainvoke({"query": state["event_summary"], "limit": 5}), timeout=_MCP_TIMEOUT_SECONDS
        )
        candidates = _unwrap_mcp_candidates(raw_candidates)
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
    claimed_skills = list(parsed.get("skills") or [])
    # Achado real de teste de carga (processo de aprendizado): o LLM
    # confirmava CSOC-001/002/003/004 (regras de correlação que EXIGEM
    # evidência real — reputação de IP confirmada, volume, payload de
    # ataque, ver correlation.json `requires`) mesmo quando o próprio
    # reasoning admitia que a evidência não estava presente — e isso
    # chegava a ser promovido para a via rápida aprendida (learning.py),
    # virando falso positivo permanente. Não precisa confiar no julgamento
    # do modelo pequeno pra isso: se o caminho de IA foi alcançado, é porque
    # `correlation_rules.evaluate()` (rules_engine.py) JÁ rodou antes e não
    # confirmou nenhuma dessas regras por fato — então uma confirmação
    # dessas aqui é garantidamente infundada, sempre removida.
    skills = [s for s in claimed_skills if s not in _EVIDENCE_REQUIRING_CORRELATION_IDS]
    if not _has_agent_context(state["event"]):
        # Achado real: Agent Threat Rule confirmada por semelhança
        # superficial ("encoding para evasão") num evento sem NENHUM sinal
        # de agente/LLM envolvido — sem isto, a mesma alucinação repetida
        # de forma consistente passa pela checagem de consistência do
        # learning.py e vira via rápida permanente para um falso positivo.
        skills = [s for s in skills if not s.startswith(_AGENT_THREAT_ID_PREFIX)]
    return {
        "matched": bool(parsed.get("matched")) and bool(skills),
        "skills": skills,
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
    # dict.fromkeys (não set) preserva ordem e deduplica — achado real: T1110
    # exato em attack_defend E network_signature (mesma técnica, duas
    # skills unificadas por técnica MITRE — ver skills_catalog.py) reportava
    # "T1110, T1110" no corpo do ticket sem isto.
    all_skills = list(dict.fromkeys(
        groups["attack_defend"]["skills"] + groups["network_signature"]["skills"] + groups["web_application"]["skills"]
    ))
    matched = any(g["matched"] for g in groups.values())
    any_degraded = any(g["degraded"] for g in groups.values())
    if matched:
        # Achado real (ticket GLPI): este caminho pula a chamada de LLM de
        # propósito (fato objetivo já confirmado, ver docstring da função) —
        # mas isso não pode significar recomendação genérica ("revisar
        # manualmente, IA não consolidou"). A técnica/regra já confirmada
        # tem descrição real (mitre.py/correlation.json); a recomendação
        # cita ela, não o mecanismo interno que gerou o veredito.
        described = [_describe_group_skill(s) for s in all_skills]
        summary = f"Correspondência confirmada por fato objetivo (não julgamento de IA): {'; '.join(described)}."
        recommendation = (
            f"Confirmar e conter a origem do evento — técnica(s)/regra(s) já confirmada(s) pelo catálogo real: "
            f"{'; '.join(described)}. Bloquear/isolar a origem (IP/conta) conforme a política de resposta desta "
            f"tática, e revisar os logs correlacionados desta origem nos últimos minutos."
        )
        return {
            "matched": matched, "matched_skills": all_skills,
            "summary": summary, "recommendation": recommendation, "groups": groups,
            "grounding_rejected": False,  # veio de fato objetivo dos grupos, nunca de opinião de LLM pra rejeitar
        }
    if any_degraded:
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
        "grounding_rejected": False,  # veio de fato objetivo dos grupos (ou ausência dele), nunca de opinião de LLM pra rejeitar
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

    # Achado real de teste de carga (causa raiz do delay evento->incidente):
    # cada evento sem match nenhum ainda gastava a 4ª chamada de LLM
    # (Supervisor) só pra "confirmar" o que os 3 grupos já disseram — mas a
    # verificação de aterramento logo abaixo (`real_skills`) já FORÇA
    # `matched=False` sempre que nenhum grupo achou skill real, não importa
    # o que o Supervisor responda. Ou seja: quando os 3 grupos avaliaram de
    # ponta a ponta (nenhum `degraded`) e nenhum achou nada, o resultado do
    # Supervisor já é determinado — chamar o LLM aqui só custa ~25s de CPU
    # (medido isoladamente: ~100s pra 4 chamadas -> ~75s pra 3) sem poder
    # mudar o veredito final. Sob rajada, isso reduz a carga agregada no
    # único worker do Ollama, encurtando a fila pra todo mundo, não só este
    # evento.
    no_group_matched_or_degraded = not any(g["matched"] or g["degraded"] for g in groups.values())
    if no_group_matched_or_degraded:
        return {"verdict": _deterministic_consolidation(groups, reason="nenhum grupo encontrou skill real, sem chamada de IA")}

    if any(g["deterministic"] for g in groups.values()):
        # Fast path proativo: pelo menos um grupo já confirmou por fato
        # objetivo (técnica reportada pela fonte bate com o catálogo) — pedir
        # ao Supervisor (LLM) para "opinar" sobre algo já certo só adiciona
        # minutos de latência de CPU sem agregar confiança nenhuma.
        return {"verdict": _deterministic_consolidation(groups, reason="técnica confirmada pela fonte, sem chamada de IA")}

    # Achado real (ticket GLPI): "recomendações genéricas, não falam o
    # propósito" — o Supervisor só via `"skills": ["T1110"]` (ID cru),
    # nunca soube de fato o que "T1110" significa, então a recomendação
    # ficava vaga por falta de conteúdo real pra citar. `groups` aqui é só
    # pra montar o PROMPT (com descrição real); `groups` (sem descrição) é
    # o que fica no estado/veredito persistido.
    described_groups = _describe_groups_for_prompt(groups)
    prompt = f"Evento:\n{state['event_summary']}\n\nVeredito dos grupos:\n{json.dumps(described_groups, ensure_ascii=False, indent=1)}"
    content = await _invoke_llm_with_retry(SUPERVISOR_PROMPT, prompt)
    parsed = _parse_json(content) if content else None
    if not parsed:
        # Sem o Supervisor conseguir consolidar (IA indisponível ou resposta
        # não é JSON), cai para o OR determinístico dos grupos (fallback
        # reativo, distinto do fast path acima).
        any_degraded = any(g["degraded"] for g in groups.values())
        reason = "IA não respondeu em JSON válido" + (" — análise parcialmente degradada" if any_degraded else "")
        return {"verdict": _deterministic_consolidation(groups, reason=reason)}
    # Achado real (via alertas de host/netstat sem sinal de ataque nenhum):
    # o Supervisor (qwen2.5:1.5b, modelo pequeno) às vezes devolve
    # "matched": true com `matched_skills` inventados (ex.: "mitre:
    # nivel=7") mesmo quando os 3 grupos, individualmente, relataram
    # "matched": false e `skills: []` — o LLM narra a descrição do evento de
    # volta como se fosse um match, sem nenhuma skill real por trás. Isso
    # virou incidente de verdade (severidade da fonte, não do achado) para
    # telemetria de host sem risco nenhum, poluindo o backlog. O Supervisor
    # pode DOWNGRADE o consenso dos grupos (dizer "não" mesmo se algum achou
    # algo — julgamento válido dele), mas nunca pode PROMOVER "nenhum grupo
    # achou skill real" para "matched" — e `matched_skills` reportado é
    # sempre a união do que os grupos realmente acharam, nunca o texto livre
    # do Supervisor.
    # dict.fromkeys (não set) preserva ordem e deduplica — a mesma técnica
    # pode exact-matchar em mais de um grupo agora que o catálogo é
    # unificado por técnica MITRE (skills_catalog.py), o que duplicava
    # "T1110, T1110" no corpo do ticket sem isto.
    real_skills = list(dict.fromkeys(
        groups["attack_defend"]["skills"] + groups["network_signature"]["skills"] + groups["web_application"]["skills"]
    ))
    llm_claimed_match = bool(parsed.get("matched"))
    matched = llm_claimed_match and bool(real_skills)
    # Sinal de qualidade de verdade (não "sem degradação de infra" — isso é
    # `degraded` acima, uma pergunta diferente): toda vez que a validação
    # PRECISOU corrigir o Supervisor, é uma alucinação real que seria um
    # incidente falso sem essa trava. Contado no dashboard como métrica
    # própria — "100% de eficiência" sozinho nunca capturava isto, porque
    # falha de aterramento nunca foi "degradação" (a chamada de LLM
    # completou normalmente, só respondeu errado).
    grounding_rejected = llm_claimed_match and not real_skills
    return {"verdict": {
        "matched": matched,
        "matched_skills": real_skills if matched else [],
        "summary": str(parsed.get("summary") or ""),
        "recommendation": str(parsed.get("recommendation") or ""),
        "groups": groups,
        "grounding_rejected": grounding_rejected,
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
