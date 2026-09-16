from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Incident, User
from ..models.incident import INCIDENT_STATUSES

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _public(i: Incident) -> dict:
    return {
        "id": i.id, "code": i.code, "title": i.title, "status": i.status,
        "severity": i.severity, "risk_score": i.risk_score, "tag": i.tag,
        "event_id": i.event_id, "created_at": i.created_at.isoformat(),
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }


class StatusUpdate(BaseModel):
    status: str


@router.get("")
async def list_incidents(
    status_filter: str | None = None,
    tag: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> list[dict]:
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if tag:
        stmt = stmt.where(Incident.tag == tag)
    rows = (await db.execute(stmt)).scalars().all()
    return [_public(i) for i in rows]


@router.patch("/{incident_id}")
async def update_status(incident_id: int, body: StatusUpdate, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"status inválido: {body.status}")
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incidente não encontrado")
    incident.status = body.status
    await db.commit()
    await db.refresh(incident)
    return _public(incident)
