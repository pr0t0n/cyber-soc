"""Orquestra o motor de regras (Supervisor LangGraph) em background após a
ingestão: nunca bloqueia o POST /api/ingest — Ollama em CPU pode levar dezenas
de segundos por chamada, e aqui rodam até 4 chamadas (3 grupos + supervisor).
"""
from __future__ import annotations

from sqlalchemy import func, select

from ..agents.graph import analyze_event
from ..db import SessionLocal
from ..models import Event, Incident


async def _next_incident_code(db) -> str:
    count = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    return f"INC-{count + 1:04d}"


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
        payload = {
            "type": event.type, "severity": event.severity, "src_ip": event.src_ip,
            "src_port": event.src_port, "dst_ip": event.dst_ip, "dst_port": event.dst_port,
            "protocol": event.protocol, "mitre": event.mitre, "behavior": event.behavior,
            "hit_count": event.hit_count, "rule_ref": event.rule_ref, "enrichment": event.enrichment,
        }
        event.rules_engine_status = "analyzing"
        await db.commit()

    async def on_progress(stage: str, group_verdict: dict) -> None:
        await _persist_progress(event_id, stage, group_verdict)

    verdict = await analyze_event(payload, on_progress=on_progress)

    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event:
            return
        event.rules_engine_verdict = verdict
        event.matched_skills = verdict.get("matched_skills") or []
        event.rules_engine_status = "matched" if verdict.get("matched") else "no_match"
        event.recommendation = verdict.get("recommendation")
        await db.commit()

        if verdict.get("matched"):
            db.add(Incident(
                code=await _next_incident_code(db),
                title=f"{event.type} — {event.src_ip or 'origem desconhecida'}",
                status="backlog",
                severity=event.severity,
                risk_score=event.risk_score,
                tag=event.tag,
                event_id=event.id,
            ))
            await db.commit()
