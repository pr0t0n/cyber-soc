"""Síntese operacional para quem não acompanhou evento a evento (analista
N3, operador de plantão) — o resto do dashboard mostra CONTADORES (quantos
incidentes, qual severidade); isto conta a HISTÓRIA: o que esta origem já
fez, desde quando, o que a plataforma já confirmou sobre ela, e o que
aconteceu no ambiente nas últimas horas — sem precisar abrir evento por
evento pra reconstruir isso na cabeça."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, Incident, LearnedPattern
from .baseline import weekly_activity
from .mitre import technique_tactic_pt

_GLPI_STATUS_LABEL = {1: "Novo", 2: "Atribuído", 3: "Planejado", 4: "Pendente", 5: "Resolvido", 6: "Fechado"}


def _age_label(delta_seconds: float) -> str:
    if delta_seconds < 3600:
        return f"{int(delta_seconds // 60)}min"
    if delta_seconds < 86400:
        return f"{delta_seconds / 3600:.1f}h"
    return f"{delta_seconds / 86400:.1f}d"


async def build_incident_narratives(db: AsyncSession, *, tag: str | None = None, limit: int = 25) -> list[dict]:
    """Uma entrada por incidente ABERTO (não concluído) — a mesma
    agregação de `rules_engine.py::_open_incident_context`, mas para
    exibição direta (não texto pra LLM), incluindo o status real do GLPI."""
    now = datetime.now(timezone.utc)
    stmt = select(Incident).where(Incident.status != "concluido").order_by(Incident.created_at.desc()).limit(limit)
    if tag:
        stmt = stmt.where(Incident.tag == tag)
    incidents = (await db.execute(stmt)).scalars().all()

    out = []
    for incident in incidents:
        fused_rows = (await db.execute(
            select(Event.src_ip, Event.dst_ip, Event.matched_skills, Event.mitre, Event.received_at)
            .where(Event.incident_id == incident.id)
        )).all()
        # O evento que ABRIU o incidente também conta, mesmo sem ter sido
        # "fundido" depois (incidents.event_id, não events.incident_id).
        opening_event = await db.get(Event, incident.event_id) if incident.event_id else None

        skills: set[str] = set()
        techniques: set[str] = set()
        src_ips: set[str] = set()
        first_seen = None
        last_seen = None
        for src_ip, dst_ip, matched_skills, mitre, received_at in fused_rows:
            skills.update(matched_skills or [])
            techniques.update(mitre or [])
            if src_ip:
                src_ips.add(src_ip)
            if received_at:
                first_seen = received_at if first_seen is None else min(first_seen, received_at)
                last_seen = received_at if last_seen is None else max(last_seen, received_at)
        if opening_event:
            skills.update(opening_event.matched_skills or [])
            techniques.update(opening_event.mitre or [])
            if opening_event.src_ip:
                src_ips.add(opening_event.src_ip)

        created = incident.created_at if incident.created_at.tzinfo else incident.created_at.replace(tzinfo=timezone.utc)
        age_seconds = (now - created).total_seconds()

        glpi_label = None
        if incident.glpi_ticket_id is not None:
            glpi_label = _GLPI_STATUS_LABEL.get(incident.glpi_status_raw, "status desconhecido")

        techniques_named = [f"{t} ({technique_tactic_pt(t)})" for t in sorted(techniques)]

        out.append({
            "incident_id": incident.id,
            "code": incident.code,
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "tag": incident.tag,
            "src_ips": sorted(src_ips),
            "event_count": len(fused_rows) + (1 if opening_event else 0),
            "techniques": sorted(techniques),
            "techniques_named": techniques_named,
            "matched_skills": sorted(skills),
            "age_label": _age_label(age_seconds),
            "glpi_ticket_id": incident.glpi_ticket_id,
            "glpi_status_label": glpi_label,
            "narrative": (
                f"{incident.code} — origem {', '.join(sorted(src_ips)) or 'desconhecida'}, ativo há {_age_label(age_seconds)}, "
                f"{len(fused_rows) + (1 if opening_event else 0)} evento(s) confirmado(s)"
                + (f", técnica(s) {', '.join(sorted(techniques))}" if techniques else "")
                + (f", ticket GLPI {glpi_label}" if glpi_label else ", sem ticket aberto")
                + "."
            ),
        })
    return out


async def build_activity_timeline(db: AsyncSession, *, limit: int = 30) -> list[dict]:
    """Linha do tempo real do ambiente — mescla 3 fontes de fato objetivo
    (nunca gerado/estimado): incidente criado, padrão promovido para
    aprendizado, e evento sinalizado como suspeito. Pedido real: "eu quero
    ver o evento sendo analisado e informado" — isto é o que aconteceu, em
    ordem, sem precisar abrir 3 páginas diferentes."""
    events: list[dict] = []

    incidents = (await db.execute(
        select(Incident).order_by(Incident.created_at.desc()).limit(limit)
    )).scalars().all()
    for incident in incidents:
        events.append({
            "kind": "incident_created",
            "timestamp": incident.created_at.isoformat(),
            "label": f"Incidente {incident.code} aberto — {incident.title}",
            "severity": incident.severity,
            "ref_id": incident.id,
        })

    patterns = (await db.execute(
        select(LearnedPattern).where(LearnedPattern.promoted.is_(True)).order_by(LearnedPattern.last_confirmed_at.desc()).limit(limit)
    )).scalars().all()
    for pattern in patterns:
        events.append({
            "kind": "pattern_learned",
            "timestamp": pattern.last_confirmed_at.isoformat(),
            "label": f"Padrão aprendido: \"{pattern.pattern_key}\" — {pattern.confirmations} confirmação(ões), promovido para via rápida",
            "severity": "info",
            "ref_id": pattern.id,
        })

    suspicious = (await db.execute(
        select(Event.id, Event.type, Event.src_ip, Event.received_at)
        .where(Event.rules_engine_status == "suspicious")
        .order_by(Event.received_at.desc()).limit(limit)
    )).all()
    for event_id, event_type, src_ip, received_at in suspicious:
        events.append({
            "kind": "suspicious_flagged",
            "timestamp": received_at.isoformat(),
            "label": f"Sinalizado para averiguação: {event_type} — origem {src_ip or 'desconhecida'}",
            "severity": "media",
            "ref_id": event_id,
        })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:limit]


async def build_traffic_baseline_overview(db: AsyncSession, *, top_n: int = 10) -> list[dict]:
    """Padrão de tráfego do ambiente pedido explicitamente — não só "quantos
    eventos", mas "isto é normal pra esta origem ou não" (mesma linha de
    base de 7 dias que já sinaliza a Watchlist, `baseline.py`), pras origens
    mais ativas nas últimas 24h."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    top_rows = (await db.execute(
        select(Event.src_ip, func.count(Event.id))
        .where(Event.src_ip.is_not(None), Event.received_at >= since_24h)
        .group_by(Event.src_ip)
        .order_by(func.count(Event.id).desc())
        .limit(top_n)
    )).all()

    out = []
    for src_ip, count_24h in top_rows:
        weekly = await weekly_activity(db, src_ip, before=now)
        avg_per_day = weekly["total_7d"] / max(weekly["days_seen"], 1) if weekly["days_seen"] else None
        out.append({
            "src_ip": src_ip,
            "events_24h": count_24h,
            "first_seen_this_window": weekly["first_seen_this_window"],
            "avg_per_day_7d": round(avg_per_day, 1) if avg_per_day is not None else None,
            "distinct_types_7d": weekly["distinct_types"],
            "is_above_baseline": bool(avg_per_day and count_24h > avg_per_day * 2) or weekly["first_seen_this_window"],
        })
    return out
