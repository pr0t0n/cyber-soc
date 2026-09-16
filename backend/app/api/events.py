from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Event, User

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
async def list_events(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    tag: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> dict:
    stmt = select(Event).order_by(Event.timestamp.desc())
    count_stmt = select(func.count(Event.id))
    if severity:
        stmt = stmt.where(Event.severity == severity)
        count_stmt = count_stmt.where(Event.severity == severity)
    if tag:
        stmt = stmt.where(Event.tag == tag)
        count_stmt = count_stmt.where(Event.tag == tag)
    total = (await db.execute(count_stmt)).scalar() or 0
    rows = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": e.id, "timestamp": e.timestamp.isoformat(), "source": e.source,
                "type": e.type, "severity": e.severity, "src_ip": e.src_ip, "dst_ip": e.dst_ip,
                "dst_port": e.dst_port, "protocol": e.protocol, "mitre": e.mitre,
                "risk_score": e.risk_score, "status": e.status, "tag": e.tag,
                "country": e.country, "city": e.city,
                "rules_engine_status": e.rules_engine_status, "matched_skills": e.matched_skills,
                "recommendation": e.recommendation,
            }
            for e in rows
        ],
    }


@router.get("/{event_id}")
async def get_event(event_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    event = await db.get(Event, event_id)
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evento não encontrado")
    return {
        "id": event.id, "timestamp": event.timestamp.isoformat(), "source": event.source,
        "type": event.type, "severity": event.severity, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
        "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.protocol,
        "mitre": event.mitre, "risk_score": event.risk_score, "behavior": event.behavior,
        "status": event.status, "enrichment": event.enrichment, "raw": event.raw,
        "tag": event.tag, "country": event.country, "city": event.city,
        "rules_engine_status": event.rules_engine_status, "matched_skills": event.matched_skills,
        "rules_engine_verdict": event.rules_engine_verdict, "recommendation": event.recommendation,
    }
