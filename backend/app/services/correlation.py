"""Correlação entre eventos — um analista de SOC nunca julga um evento
isolado: uma origem que gerou vários eventos em poucos minutos é, por si só,
um sinal (varredura, força bruta distribuída por várias regras, movimento
lateral), mesmo que nenhum evento individual pareça grave sozinho. Hoje isso
não existia — cada evento era avaliado 100% isolado do que aconteceu antes
ou depois na mesma origem."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, Incident

CORRELATION_WINDOW_MINUTES = 10


async def count_recent_events_from_ip(db: AsyncSession, src_ip: str | None, *, before: datetime) -> int:
    """Quantos eventos (de qualquer tipo/fonte) essa origem gerou nos últimos
    `CORRELATION_WINDOW_MINUTES`, incluindo o próprio evento atual — 1 sempre
    que a origem só apareceu essa vez."""
    if not src_ip:
        return 0
    since = before - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    stmt = select(func.count(Event.id)).where(
        Event.src_ip == src_ip, Event.received_at >= since, Event.received_at <= before
    )
    return int((await db.execute(stmt)).scalar() or 0)


async def find_open_incident_id(db: AsyncSession, src_ip: str | None, *, before: datetime) -> int | None:
    """Alert Fusion: um analista de SOC não deveria precisar abrir N tickets
    para a mesma origem gerando M eventos confirmados na mesma janela de 10
    minutos (força bruta reportando tentativa após tentativa, cada uma
    casando a mesma regra de correlação). Reaproveita a mesma janela de
    `count_recent_events_from_ip` para achar o incidente mais recente, ainda
    não concluído, aberto por outro evento confirmado desta origem — se
    existir, o chamador deve anexar o evento atual a ele em vez de abrir mais
    um incidente duplicado."""
    if not src_ip:
        return None
    since = before - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    stmt = (
        select(Incident.id)
        .join(Event, Event.incident_id == Incident.id)
        .where(
            Event.src_ip == src_ip, Event.received_at >= since, Event.received_at <= before,
            Incident.status != "concluido",
        )
        .order_by(Event.received_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()
