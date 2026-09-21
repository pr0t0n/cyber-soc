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
CAMPAIGN_LOOKBACK_DAYS = 7
MULTI_ORIGIN_TARGET_WINDOW_MINUTES = 30


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


async def find_technique_matches_in_other_open_incidents(
    db: AsyncSession, mitre: list[str], *, exclude_src_ip: str | None, before: datetime,
    window_days: int = CAMPAIGN_LOOKBACK_DAYS,
) -> list[tuple[str, str, str]]:
    """Segundo hop de correlação: `_open_incident_context` (rules_engine.py)
    só olha a MESMA origem dentro do MESMO incidente — isto olha PARA FORA,
    outros incidentes abertos de origem DIFERENTE que já tiveram a MESMA
    técnica MITRE CONFIRMADA (`rules_engine_status="matched"`, nunca a
    alegação crua da própria fonte) nos últimos `window_days` dias. Padrão
    de campanha (mesma técnica, origens diferentes), não origem isolada.
    Retorna (código do incidente, origem, técnica em comum) por ocorrência."""
    if not mitre:
        return []
    since = before - timedelta(days=window_days)
    stmt = (
        select(Incident.code, Event.src_ip, Event.mitre)
        .join(Event, Event.incident_id == Incident.id)
        .where(
            Incident.status != "concluido",
            Event.rules_engine_status == "matched",
            Event.received_at >= since,
            Event.received_at <= before,
        )
    )
    if exclude_src_ip:
        stmt = stmt.where(Event.src_ip != exclude_src_ip)
    rows = (await db.execute(stmt)).all()
    wanted = set(mitre)
    matches: list[tuple[str, str, str]] = []
    for code, src_ip, event_mitre in rows:
        overlap = wanted & set(event_mitre or [])
        if overlap:
            matches.append((code, src_ip, ", ".join(sorted(overlap))))
    return matches


async def count_distinct_origins_targeting(
    db: AsyncSession, dst_ip: str | None, *, exclude_src_ip: str | None, before: datetime,
    window_minutes: int = MULTI_ORIGIN_TARGET_WINDOW_MINUTES,
) -> int:
    """Segundo hop de correlação: quantas origens DISTINTAS (excluindo a
    atual) miraram o mesmo `dst_ip` nos últimos `window_minutes` —
    `count_recent_events_from_ip` só enxerga repetição da MESMA origem;
    isto enxerga múltiplos atacantes mirando o MESMO ativo ao mesmo tempo,
    sinal que `asset_risk.py` já expõe como saída (contagem de origens por
    ativo) mas que até aqui nunca entrava como ENTRADA da análise."""
    if not dst_ip:
        return 0
    since = before - timedelta(minutes=window_minutes)
    stmt = (
        select(Event.src_ip)
        .where(
            Event.dst_ip == dst_ip, Event.received_at >= since, Event.received_at <= before,
            Event.src_ip.is_not(None),
        )
        .distinct()
    )
    if exclude_src_ip:
        stmt = stmt.where(Event.src_ip != exclude_src_ip)
    rows = (await db.execute(stmt)).scalars().all()
    return len(set(rows))
