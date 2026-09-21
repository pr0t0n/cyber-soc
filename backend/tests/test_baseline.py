"""Linha de base de 7 dias por origem (app/services/baseline.py) — sinal de
'essa origem nunca fez isso antes', independente de qualquer skill do
catálogo ter casado."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Event
from app.services import baseline

_NOW = datetime(2026, 6, 25, 12, 0, tzinfo=timezone.utc)


async def _add_event(db, *, src_ip: str, received_at, type_="Evento de teste"):
    db.add(Event(
        source="generic", type=type_, severity="baixa", src_ip=src_ip,
        timestamp=received_at, received_at=received_at, mitre=[],
    ))
    await db.commit()


async def test_weekly_activity_empty_for_ip_with_no_history():
    async with SessionLocal() as db:
        weekly = await baseline.weekly_activity(db, "203.0.113.9", before=_NOW)
        assert weekly == {"total_7d": 0, "days_seen": 0, "first_seen_this_window": True, "distinct_types": []}


async def test_weekly_activity_counts_events_within_window_only():
    async with SessionLocal() as db:
        await _add_event(db, src_ip="203.0.113.9", received_at=_NOW - timedelta(days=2))
        await _add_event(db, src_ip="203.0.113.9", received_at=_NOW - timedelta(days=3))
        await _add_event(db, src_ip="203.0.113.9", received_at=_NOW - timedelta(days=10))  # fora da janela
        await _add_event(db, src_ip="198.51.100.1", received_at=_NOW - timedelta(days=1))  # outra origem

        weekly = await baseline.weekly_activity(db, "203.0.113.9", before=_NOW)
        assert weekly["total_7d"] == 2
        assert weekly["days_seen"] == 2
        assert weekly["first_seen_this_window"] is False


async def test_anomaly_reason_none_below_burst_threshold():
    weekly = {"total_7d": 0, "days_seen": 0, "first_seen_this_window": True, "distinct_types": []}
    assert baseline.anomaly_reason(weekly, current_correlated_count=2) is None


async def test_anomaly_reason_flags_new_origin_with_a_burst():
    weekly = {"total_7d": 0, "days_seen": 0, "first_seen_this_window": True, "distinct_types": []}
    reason = baseline.anomaly_reason(weekly, current_correlated_count=6)
    assert reason is not None
    assert "nova" in reason.lower()


async def test_anomaly_reason_flags_burst_far_above_historical_average():
    # Média histórica de 1 evento/dia — uma rajada de 10 agora é bem acima.
    weekly = {"total_7d": 7, "days_seen": 7, "first_seen_this_window": False, "distinct_types": []}
    reason = baseline.anomaly_reason(weekly, current_correlated_count=10)
    assert reason is not None
    assert "média histórica" in reason


async def test_anomaly_reason_none_for_established_normal_volume():
    # Origem que sempre gera bastante evento — volume atual dentro do padrão.
    weekly = {"total_7d": 70, "days_seen": 7, "first_seen_this_window": False, "distinct_types": []}
    assert baseline.anomaly_reason(weekly, current_correlated_count=12) is None
