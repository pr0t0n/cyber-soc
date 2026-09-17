"""Orquestra o motor de regras (Supervisor LangGraph) em background após a
ingestão: nunca bloqueia o POST /api/ingest — Ollama em CPU pode levar dezenas
de segundos por chamada, e aqui rodam até 4 chamadas (3 grupos + supervisor).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..agents.graph import analyze_event
from ..db import SessionLocal
from ..models import SEVERITIES, Event, Incident
from . import correlation_rules, skill_signature_match
from .correlation import count_recent_events_from_ip, find_open_incident_id
from .event_triage import (
    deterministic_verdict,
    fast_lane_verdict,
    is_compliance_noise,
    is_network_traffic,
    non_network_fast_lane_verdict,
)
from .notify import dispatch_incident_notification

# Limita quantos eventos passam pela análise de IA (LangGraph + Ollama) ao
# mesmo tempo. Ollama neste ambiente é um único worker de CPU — disparar
# dezenas de eventos de uma vez (ex.: rajada de SCA no primeiro scan de um
# agente novo, ou reprocessamento de backlog após um restart) não paraleliza
# de verdade, só faz o processo da API competir por memória/conexões e
# derruba a responsividade de tudo (login incluído, já observado). Isso
# enfileira: os eventos além do limite esperam a vez em vez de competir.
_ANALYSIS_CONCURRENCY = asyncio.Semaphore(2)


async def _next_incident_code(db) -> str:
    count = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    return f"INC-{count + 1:04d}"


def _severity_rank(severity: str) -> int:
    """Menor índice = mais grave. Ingestão genérica aceita qualquer string de
    severidade vinda da fonte (não só as de `SEVERITIES`) — cai para "menos
    grave que tudo" em vez de derrubar a fusão de incidente por um valor
    inesperado."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _escalate_risk_score(base_score: int, *, correlated_count: int | None, deterministic: bool) -> int:
    """Risk-Based Alerting: a nota de risco calculada no ingest (porta/
    protocolo/reputação de IP — app/services/threat_intel.py) ainda não sabe
    se a skill casou nem quantos eventos correlacionados a mesma origem já
    gerou. Um "PowerShell comum" e um "PowerShell com skill confirmada + 12
    eventos correlacionados da mesma origem" não podem carregar o mesmo risco
    só porque a porta é igual — ver seção 6 (Risk-Based Alerting) da análise
    de arquitetura. Bônus por confirmação objetiva (correlação determinística,
    sem opinião de LLM) pesa mais que confirmação via julgamento do modelo."""
    score = base_score + (15 if deterministic else 10)
    if correlated_count and correlated_count > 1:
        score += min((correlated_count - 1) * 2, 20)
    return min(100, score)


async def _open_or_fuse_incident(db, event: Event) -> None:
    """Alert Fusion (seção 3 da análise de arquitetura): a mesma origem
    confirmada mais de uma vez na mesma janela de correlação (10 min) deve
    virar UM incidente que acumula evidência, não N incidentes duplicados que
    obrigam o analista a investigar a mesma origem várias vezes separadamente.

    Dispara notificação/ticket (`notify.py`) só na criação e quando o
    incidente de fato escala (risco ou severidade pioram) — nunca a cada
    evento fundido, ou um port scan com 50 eventos correlacionados viraria 50
    mensagens idênticas no Slack/Teams e 50 chamados duplicados. "Escalar" aqui
    é especificamente mudança de SEVERIDADE, não qualquer alta de risk_score —
    `correlated_count` sobe a cada evento fundido, então o bônus de correlação
    em `_escalate_risk_score` por si só faria o risco subir um pouco a cada
    fusão (ex.: 50 eventos de um port scan = 50 pequenas altas de risco), o
    que redispararia notificação a cada uma sem trazer sinal novo nenhum."""
    existing_id = await find_open_incident_id(db, event.src_ip, before=event.received_at)
    if existing_id is not None:
        incident = await db.get(Incident, existing_id)
        event.incident_id = incident.id
        if event.risk_score > incident.risk_score:
            incident.risk_score = event.risk_score
        severity_escalated = _severity_rank(event.severity) < _severity_rank(incident.severity)
        if severity_escalated:
            incident.severity = event.severity
        await db.commit()
        if severity_escalated:
            await dispatch_incident_notification(db, incident)
        return

    incident = Incident(
        code=await _next_incident_code(db),
        title=f"{event.type} — {event.src_ip or 'origem desconhecida'}",
        status="backlog",
        severity=event.severity,
        risk_score=event.risk_score,
        tag=event.tag,
        event_id=event.id,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    event.incident_id = incident.id
    await db.commit()
    await dispatch_incident_notification(db, incident)
    await db.commit()


_STAGE_ORDER = ("attack_defend", "network_signature", "web_application")


async def _persist_progress(event_id: int, stage: str, group_verdict: dict) -> None:
    """Callback do grafo (app/agents/graph.py) — grava o veredito de cada grupo
    assim que ele termina, para a tela Eventos poder mostrar o agente
    trabalhando em tempo real (em vez de só no fim, até ~900s depois)."""
    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event or event.rules_engine_status not in ("pending", "analyzing"):
            return
        trace = dict(event.rules_engine_verdict or {})
        groups = dict(trace.get("groups") or {})
        groups[stage] = group_verdict
        trace["groups"] = groups
        trace["stage"] = stage
        trace["stages_done"] = len(groups)
        trace["stages_total"] = len(_STAGE_ORDER)
        event.rules_engine_verdict = trace
        event.rules_engine_status = "analyzing"
        await db.commit()


async def run_rules_engine_for_event(event_id: int) -> None:
    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event:
            return

        event.correlated_count = await count_recent_events_from_ip(db, event.src_ip, before=event.received_at)

        if is_compliance_noise(event.raw or {}):
            # Via rápida: achado de compliance/inventário (SCA/rootcheck) —
            # veredito determinístico, sem gastar o único worker de LLM com
            # algo que não é um comportamento de ataque. Ver event_triage.py.
            verdict = fast_lane_verdict(event.type)
            event.rules_engine_verdict = verdict
            event.matched_skills = []
            event.rules_engine_status = "informational"
            event.recommendation = verdict["recommendation"]
            event.analyzed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        if not is_network_traffic(src_ip=event.src_ip, dst_ip=event.dst_ip):
            # Escopo do produto: só analisamos tráfego de rede. Telemetria de
            # host sem IP nenhum (FIM, rootcheck, syscollector, ciclo de vida
            # do agente, sudo/tela bloqueada) nunca chega ao motor de IA — só
            # o rótulo de compliance (acima) tinha esse tratamento antes;
            # isso generaliza para qualquer evento sem sinal de rede.
            verdict = non_network_fast_lane_verdict(event.type)
            event.rules_engine_verdict = verdict
            event.matched_skills = []
            event.rules_engine_status = "informational"
            event.recommendation = verdict["recommendation"]
            event.analyzed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        payload = {
            "type": event.type, "severity": event.severity, "src_ip": event.src_ip,
            "src_port": event.src_port, "dst_ip": event.dst_ip, "dst_port": event.dst_port,
            "protocol": event.protocol, "mitre": event.mitre, "behavior": event.behavior,
            "hit_count": event.hit_count, "rule_ref": event.rule_ref, "enrichment": event.enrichment,
            "correlated_count": event.correlated_count,
        }

        # Via rápida determinística: duas fontes de fato objetivo, sem RAG/
        # LLM — (1) app/services/correlation_rules.py (CSOC-00x: porta,
        # tentativas/correlação, reputação de IP, já calculadas acima e no
        # ingest) e (2) app/services/skill_signature_match.py (SID Suricata /
        # regra ModSecurity que a própria fonte já relatou E que o catálogo
        # real de skills reconhece — mesmo princípio de _exact_id_matches
        # para MITRE ATT&CK em app/agents/graph.py, mas para os OUTROS
        # catálogos: Suricata, ModSecurity). Isso é o que faz a decisão
        # acontecer em segundos em vez de esperar o grafo sequencial (3
        # grupos + supervisor, cada um em Ollama CPU) mesmo para assinaturas
        # de rede reais e já catalogadas — só o que sobra disso (nenhuma das
        # duas fontes reconheceu nada) vai para o motor de IA.
        deterministic_matches = correlation_rules.evaluate(payload) + skill_signature_match.evaluate(event.raw or {})
        fast_verdict = deterministic_verdict(deterministic_matches) if deterministic_matches else None
        if fast_verdict is not None:
            event.rules_engine_verdict = fast_verdict
            event.matched_skills = fast_verdict["matched_skills"]
            event.rules_engine_status = "matched"
            event.recommendation = fast_verdict["recommendation"]
            event.risk_score = _escalate_risk_score(
                event.risk_score, correlated_count=event.correlated_count, deterministic=True,
            )
            event.analyzed_at = datetime.now(timezone.utc)
            await db.commit()
            await _open_or_fuse_incident(db, event)
            return

        event.rules_engine_status = "analyzing"
        await db.commit()

    async def on_progress(stage: str, group_verdict: dict) -> None:
        await _persist_progress(event_id, stage, group_verdict)

    async with _ANALYSIS_CONCURRENCY:
        verdict = await analyze_event(payload, on_progress=on_progress)

    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event:
            return
        event.rules_engine_verdict = verdict
        event.matched_skills = verdict.get("matched_skills") or []
        event.rules_engine_status = "matched" if verdict.get("matched") else "no_match"
        event.recommendation = verdict.get("recommendation")
        if verdict.get("matched"):
            event.risk_score = _escalate_risk_score(
                event.risk_score, correlated_count=event.correlated_count, deterministic=False,
            )
        event.analyzed_at = datetime.now(timezone.utc)
        await db.commit()

        if verdict.get("matched"):
            await _open_or_fuse_incident(db, event)
