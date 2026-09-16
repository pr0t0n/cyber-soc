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


async def run_rules_engine_for_event(event_id: int) -> None:
    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event:
            return
        payload = {
            "type": event.type, "severity": event.severity, "src_ip": event.src_ip,
            "src_port": event.src_port, "dst_ip": event.dst_ip, "dst_port": event.dst_port,
            "protocol": event.protocol, "mitre": event.mitre, "behavior": event.behavior,
        }
        verdict = await analyze_event(payload)

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
