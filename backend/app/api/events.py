import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Event, User

router = APIRouter(prefix="/api/events", tags=["events"])

_RAW_SCAN_WINDOW = 2000


@router.get("/raw")
async def list_raw_events(
    q: str | None = None,
    tag: str | None = None,
    source: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> dict:
    """Acesso direto ao dado bruto do SIEM (Wazuh/Elastic/generic), sem
    nenhuma camada de interpretação da IA — existe porque o analista às vezes
    precisa ver exatamente o que a fonte mandou, não o veredito do motor de
    regras sobre isso. Busca textual (`q`) roda em memória sobre uma janela
    recente (não em SQL) para funcionar igual em Postgres e SQLite."""
    stmt = select(Event).order_by(Event.received_at.desc())
    if tag:
        stmt = stmt.where(Event.tag == tag)
    if source:
        stmt = stmt.where(Event.source == source)
    rows = (await db.execute(stmt.limit(_RAW_SCAN_WINDOW))).scalars().all()
    if q:
        needle = q.lower()
        rows = [e for e in rows if needle in json.dumps(e.raw, ensure_ascii=False).lower()]
    total = len(rows)
    page = rows[offset : offset + limit]
    return {
        "total": total,
        "items": [
            {
                "id": e.id, "timestamp": e.timestamp.isoformat(), "received_at": e.received_at.isoformat(),
                "source": e.source, "tag": e.tag,
                "rule_id": (e.raw.get("rule") or {}).get("id"),
                "rule_level": (e.raw.get("rule") or {}).get("level"),
                "rule_groups": (e.raw.get("rule") or {}).get("groups"),
                "full_log": e.raw.get("full_log"),
                "rules_engine_status": e.rules_engine_status,
            }
            for e in page
        ],
    }


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
                "hit_count": e.hit_count, "rule_ref": e.rule_ref, "correlated_count": e.correlated_count,
                "rules_engine_status": e.rules_engine_status, "matched_skills": e.matched_skills,
                "recommendation": e.recommendation, "analyzed_at": e.analyzed_at.isoformat() if e.analyzed_at else None,
                "stages_done": (e.rules_engine_verdict or {}).get("stages_done", 0),
                "stages_total": (e.rules_engine_verdict or {}).get("stages_total", 3),
                "current_stage": (e.rules_engine_verdict or {}).get("stage"),
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
        "hit_count": event.hit_count, "rule_ref": event.rule_ref, "correlated_count": event.correlated_count,
        "rules_engine_status": event.rules_engine_status, "matched_skills": event.matched_skills,
        "rules_engine_verdict": event.rules_engine_verdict, "recommendation": event.recommendation,
        "analyzed_at": event.analyzed_at.isoformat() if event.analyzed_at else None,
    }
