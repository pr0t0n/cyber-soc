from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Connector, Event, Incident, User
from ..services.mitre import MITRE_TACTICS

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SEVERITIES = ("critica", "alta", "media", "baixa", "info")


def _tag_filter(stmt: Select, tag: str | None) -> Select:
    return stmt.where(Event.tag == tag) if tag else stmt


@router.get("/tags")
async def tags(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Tags de cliente distintas vistas nos eventos — alimenta o seletor do
    dashboard ("ver só os eventos da VALID")."""
    rows = (await db.execute(select(Event.tag).where(Event.tag.is_not(None)).distinct())).scalars().all()
    return {"tags": sorted(rows)}


@router.get("/summary")
async def summary(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    now = datetime.now(timezone.utc)
    today_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)

    counts = {s: 0 for s in SEVERITIES}
    rows = (
        await db.execute(_tag_filter(select(Event.severity, func.count(Event.id)), tag).group_by(Event.severity))
    ).all()
    for severity, count in rows:
        counts[severity] = int(count or 0)

    events_today = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.timestamp >= today_start))
    ).scalar() or 0)

    avg_risk = (await db.execute(_tag_filter(select(func.avg(Event.risk_score)), tag))).scalar()

    seen = {
        t for (items,) in (await db.execute(_tag_filter(select(Event.mitre), tag))).all() for t in (items or [])
    }
    total_techniques = sum(len(t["techniques"]) for t in MITRE_TACTICS)
    covered = len([t for t in seen if t in {tech for tac in MITRE_TACTICS for tech in tac["techniques"]}])
    mitre_pct = round(covered * 100 / total_techniques) if total_techniques else 0

    return {
        "date": now.isoformat(),
        "severity_counts": counts,
        "events_today": events_today,
        "critical_active": counts.get("critica", 0),
        "avg_risk_score": round(float(avg_risk), 1) if avg_risk is not None else 0.0,
        "mitre_coverage_pct": mitre_pct,
    }


@router.get("/eps")
async def eps(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """EPS + funil: TOTAL de EPS ingerido -> motor de regras de IA (Supervisor
    LangGraph + skills ATT&CK/D3FEND/Suricata/ModSecurity via RAG/MCP,
    `app/agents/graph.py`) -> Incidentes. O estágio do meio é
    `rules_engine_status == "matched"` (dado real da análise, roda em
    background após a ingestão — não é um limiar estático)."""
    now = datetime.now(timezone.utc)
    count_1m = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.received_at >= now - timedelta(minutes=1)))
    ).scalar() or 0)
    count_5m = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.received_at >= now - timedelta(minutes=5)))
    ).scalar() or 0)

    total = int((await db.execute(_tag_filter(select(func.count(Event.id)), tag))).scalar() or 0)
    matched_stmt = _tag_filter(select(func.count(Event.id)), tag).where(Event.rules_engine_status == "matched")
    matched = int((await db.execute(matched_stmt)).scalar() or 0)
    pending_stmt = _tag_filter(select(func.count(Event.id)), tag).where(
        Event.rules_engine_status.in_(("pending", "analyzing"))
    )
    pending = int((await db.execute(pending_stmt)).scalar() or 0)

    incident_count_stmt = select(func.count(Incident.id))
    if tag:
        incident_count_stmt = incident_count_stmt.where(Incident.tag == tag)
    incidents_total = int((await db.execute(incident_count_stmt)).scalar() or 0)

    funnel = [
        {"stage": "eps", "label": "Total de EPS", "count": total, "pct_of_total": 100.0 if total else 0.0},
        {"stage": "rules_engine", "label": "Motor de Regras (IA)", "count": matched,
         "pct_of_total": round(matched * 100 / total, 1) if total else 0.0},
        {"stage": "incident", "label": "Incidentes", "count": incidents_total,
         "pct_of_total": round(incidents_total * 100 / total, 2) if total else 0.0},
    ]

    return {
        "eps": {"current": round(count_1m / 60, 2), "avg_5m": round(count_5m / 300, 2)},
        "total_events": total,
        "pending_analysis": pending,
        "funnel": funnel,
    }


@router.get("/mitre-heatmap")
async def mitre_heatmap(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    rows = (await db.execute(_tag_filter(select(Event.mitre), tag))).all()
    counts: dict[str, int] = {}
    for (items,) in rows:
        for tech in items or []:
            counts[tech] = counts.get(tech, 0) + 1

    tactics = []
    max_count = 0
    for tactic in MITRE_TACTICS:
        cells = []
        for tech in tactic["techniques"]:
            c = counts.get(tech, 0)
            max_count = max(max_count, c)
            cells.append({"id": tech, "count": c})
        tactics.append({"name": tactic["name"], "techniques": cells})
    return {"tactics": tactics, "max_count": max_count}


@router.get("/risk-heatmap")
async def risk_heatmap(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Heat map de risco do ambiente: dia da semana x hora, célula = risco médio
    dos eventos daquela janela (não apenas volume) dos últimos 7 dias."""
    since = datetime.now(timezone.utc) - timedelta(days=7)
    grid = [[0.0] * 24 for _ in range(7)]
    counts = [[0] * 24 for _ in range(7)]

    stmt = _tag_filter(select(Event.timestamp, Event.risk_score), tag).where(Event.timestamp >= since)
    rows = (await db.execute(stmt)).all()
    for ts, risk in rows:
        aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        d, h = aware.weekday(), aware.hour
        grid[d][h] += risk or 0
        counts[d][h] += 1

    for d in range(7):
        for h in range(24):
            grid[d][h] = round(grid[d][h] / counts[d][h], 1) if counts[d][h] else 0.0

    return {"days": ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"], "grid": grid, "max_risk": 100}


@router.get("/world-map")
async def world_map(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Pins do world map: origem geográfica dos eventos (agrupado por
    cidade/coordenada), com contagem e severidade máxima observada."""
    stmt = _tag_filter(
        select(Event.country, Event.city, Event.lat, Event.lon, Event.severity, Event.risk_score), tag
    ).where(Event.lat.is_not(None), Event.lon.is_not(None))
    rows = (await db.execute(stmt)).all()

    rank = {"critica": 4, "alta": 3, "media": 2, "baixa": 1, "info": 0}
    points: dict[tuple, dict] = {}
    for country, city, lat, lon, severity, risk in rows:
        key = (round(lat, 1), round(lon, 1))
        p = points.setdefault(key, {
            "country": country, "city": city, "lat": lat, "lon": lon,
            "count": 0, "max_severity": "info", "max_risk": 0,
        })
        p["count"] += 1
        p["max_risk"] = max(p["max_risk"], risk or 0)
        if rank.get(severity, 0) > rank.get(p["max_severity"], 0):
            p["max_severity"] = severity

    return {"points": list(points.values())}


@router.get("/connectors-status")
async def connectors_status(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """"Tratativa atual" — status das plataformas de acesso (conectores) configuradas."""
    rows = (await db.execute(select(Connector))).scalars().all()
    return {
        "total": len(rows),
        "items": [
            {
                "id": c.id, "name": c.name, "kind": c.kind, "type": c.type,
                "status": c.status, "last_test": c.last_test,
                "client_tag": (c.config or {}).get("client_tag"),
            }
            for c in rows
        ],
    }


@router.get("/incidents-status")
async def incidents_status(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Status dos incidentes internos (BackLog / Em Andamento / Concluído)."""
    stmt = select(Incident.status, func.count(Incident.id))
    if tag:
        stmt = stmt.where(Incident.tag == tag)
    rows = (await db.execute(stmt.group_by(Incident.status))).all()
    by_status = {s: int(c) for s, c in rows}

    recent_stmt = select(Incident).order_by(Incident.created_at.desc()).limit(8)
    if tag:
        recent_stmt = recent_stmt.where(Incident.tag == tag)
    recent = (await db.execute(recent_stmt)).scalars().all()

    return {
        "summary": {
            "backlog": by_status.get("backlog", 0),
            "em_andamento": by_status.get("em_andamento", 0),
            "concluido": by_status.get("concluido", 0),
            "total": sum(by_status.values()),
        },
        "recent": [
            {"id": i.id, "code": i.code, "title": i.title, "status": i.status, "severity": i.severity, "event_id": i.event_id}
            for i in recent
        ],
    }


@router.get("/agent-activity")
async def agent_activity(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Feed de atividade do agente (Supervisor LangGraph) — o que a IA está
    fazendo/decidindo agora, evento a evento. Existe para dar visibilidade
    real do processo (RAG + grupos + Supervisor), não só o veredito final."""
    stmt = _tag_filter(
        select(
            Event.id, Event.type, Event.severity, Event.src_ip, Event.tag,
            Event.rules_engine_status, Event.matched_skills, Event.recommendation,
            Event.rules_engine_verdict, Event.received_at,
        ),
        tag,
    ).order_by(Event.received_at.desc()).limit(12)
    rows = (await db.execute(stmt)).all()

    items = []
    for eid, etype, severity, src_ip, etag, rstatus, skills, rec, verdict, received_at in rows:
        verdict = verdict or {}
        groups = verdict.get("groups") or {}
        items.append({
            "event_id": eid, "type": etype, "severity": severity, "src_ip": src_ip, "tag": etag,
            "rules_engine_status": rstatus, "matched_skills": skills or [], "recommendation": rec,
            "stages_done": verdict.get("stages_done", len(groups)), "stages_total": verdict.get("stages_total", 3),
            "current_stage": verdict.get("stage"),
            "received_at": received_at.isoformat() if received_at else None,
        })
    return {"items": items}


@router.get("/tickets-status")
async def tickets_status(_: User = Depends(current_user)) -> dict:
    """Status dos chamados no ITSM externo (Jira/GLPI) — distinto do
    /incidents-status interno. A integração ainda não existe: estrutura
    pronta, sem dado fabricado."""
    return {
        "summary": {"abertos": 0, "em_analise": 0, "fechados": 0, "total": 0},
        "recent": [],
        "note": "Integração ITSM (Jira/GLPI) ainda não configurada.",
    }
