from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Incident, User
from ..models.incident import INCIDENT_STATUSES
from ..services.notify import sync_all_glpi_statuses

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _public(i: Incident) -> dict:
    return {
        "id": i.id, "code": i.code, "title": i.title, "status": i.status,
        "severity": i.severity, "risk_score": i.risk_score, "tag": i.tag,
        "event_id": i.event_id, "created_at": i.created_at.isoformat(),
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        # `glpi_ticket_id` presente == status vem do GLPI, não é editável
        # aqui (ver `update_status` abaixo) — pedido real: o GLPI é quem
        # manda, não uma lista suspensa local desconectada.
        "glpi_ticket_id": i.glpi_ticket_id,
        "glpi_status_raw": i.glpi_status_raw,
        "glpi_synced_at": i.glpi_synced_at.isoformat() if i.glpi_synced_at else None,
    }


class StatusUpdate(BaseModel):
    status: str


@router.get("")
async def list_incidents(
    status_filter: str | None = None,
    tag: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> dict:
    # Achado real: sem paginação, uma base com centenas de incidentes trazia
    # TODOS de uma vez pro Resposta/Incidentes — mesmo formato de `GET
    # /api/events` (`total`+`items`), pra a mesma paginação de UI funcionar
    # igual nas duas listas.
    stmt = select(Incident).order_by(Incident.created_at.desc())
    count_stmt = select(func.count(Incident.id))
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
        count_stmt = count_stmt.where(Incident.status == status_filter)
    if tag:
        stmt = stmt.where(Incident.tag == tag)
        count_stmt = count_stmt.where(Incident.tag == tag)
    total = (await db.execute(count_stmt)).scalar() or 0
    rows = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": [_public(i) for i in rows]}


@router.patch("/{incident_id}")
async def update_status(incident_id: int, body: StatusUpdate, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"status inválido: {body.status}")
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incidente não encontrado")
    if incident.glpi_ticket_id is not None:
        # Pedido real: uma vez que existe ticket GLPI, ele é o sistema de
        # registro — editar o status aqui faria os dois lados divergirem em
        # silêncio. Use `POST /sync-glpi` pra puxar o status real de lá.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Incidente {incident.code} tem ticket GLPI #{incident.glpi_ticket_id} — status é sincronizado de lá, não editável aqui.",
        )
    incident.status = body.status
    await db.commit()
    await db.refresh(incident)
    return _public(incident)


@router.post("/sync-glpi")
async def sync_glpi(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    return await sync_all_glpi_statuses(db)
