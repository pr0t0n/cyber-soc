"""Linha de base comportamental por origem numa janela de 7 dias — um
analista de SOC nunca julga um evento isolado nem só pelos últimos 10
minutos (`correlation.py`, correlação de curto prazo): uma origem que nunca
apareceu na semana e de repente gera uma rajada é um sinal distinto de uma
origem que sempre gerou esse volume. Sem isso, todo evento era julgado como
se a história da origem começasse agora — mesmo quando a IA não reconhece
nenhuma skill específica, "essa origem nunca fez isso antes" já é sinal
suficiente para marcar como suspeito em vez de descartar."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event
from .correlation import CORRELATION_WINDOW_MINUTES

BASELINE_WINDOW_DAYS = 7
# Menor que o limiar de `correlated_count` do CSOC-002 (5, `correlation_rules.py`)
# de propósito: qualquer rajada >=5 já vira "varredura confirmada" pela via
# rápida determinística ANTES de chegar aqui — este código só é alcançado
# quando NENHUMA regra determinística nem a IA reconheceram nada, então o
# sinal de origem teria que ser mais sensível que o da via rápida para não
# ficar morto (código nunca executado na prática).
_BURST_MIN_EVENTS = 3
_BURST_VS_AVG_MULTIPLIER = 3


async def weekly_activity(db: AsyncSession, src_ip: str | None, *, before: datetime) -> dict:
    """Histórico real desta origem nos últimos `BASELINE_WINDOW_DAYS` dias —
    excluindo não só o próprio evento, mas toda a janela de correlação de
    curto prazo (`CORRELATION_WINDOW_MINUTES`, `correlation.py`) que
    antecede ele. Sem essa exclusão, uma rajada de uma origem nova se
    autoinflava: os primeiros eventos da PRÓPRIA rajada (todos nos últimos
    minutos) já contavam como "histórico", fazendo a média subir junto e
    escondendo exatamente o padrão que devíamos sinalizar — a linha de base
    tem que refletir o comportamento ANTES da rajada atual, não durante."""
    if not src_ip:
        return {"total_7d": 0, "days_seen": 0, "first_seen_this_window": True, "distinct_types": []}
    since = before - timedelta(days=BASELINE_WINDOW_DAYS)
    burst_cutoff = before - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    stmt = select(Event.received_at, Event.type).where(
        Event.src_ip == src_ip, Event.received_at >= since, Event.received_at < burst_cutoff,
    )
    rows = (await db.execute(stmt)).all()
    total = len(rows)
    days_seen = len({r.date() for r, _ in rows})
    distinct_types = sorted({t for _, t in rows})
    return {
        "total_7d": total,
        "days_seen": days_seen,
        "first_seen_this_window": total == 0,
        "distinct_types": distinct_types[:5],
    }


def anomaly_reason(weekly: dict, *, current_correlated_count: int) -> str | None:
    """Sinal estatístico simples e defensável — a mesma heurística que um
    analista N1 aplicaria de cabeça ('essa origem nunca fez isso antes'),
    não aprendizado de máquina. `None` quando não há nada fora do padrão."""
    if current_correlated_count < _BURST_MIN_EVENTS:
        return None
    if weekly["first_seen_this_window"]:
        return (
            f"Origem nova — sem nenhum evento nos últimos {BASELINE_WINDOW_DAYS} dias antes desta "
            f"rajada de {current_correlated_count} evento(s) correlacionado(s)."
        )
    avg_per_day = weekly["total_7d"] / max(weekly["days_seen"], 1)
    if current_correlated_count > avg_per_day * _BURST_VS_AVG_MULTIPLIER:
        return (
            f"Rajada atual ({current_correlated_count} evento(s) correlacionado(s)) muito acima da "
            f"média histórica desta origem ({avg_per_day:.1f}/dia nos últimos {BASELINE_WINDOW_DAYS} dias)."
        )
    return None
