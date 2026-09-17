"""Um analista de SOC nunca julga um evento isolado — várias ocorrências da
mesma origem em poucos minutos é sinal por si só (varredura, força bruta),
mesmo que nenhum evento individual pareça grave sozinho."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Event
from app.services.correlation import CORRELATION_WINDOW_MINUTES, count_recent_events_from_ip


async def _make_event(db, *, src_ip: str, received_at: datetime) -> Event:
    event = Event(
        timestamp=received_at, received_at=received_at,
        source="generic", type="teste", severity="info", src_ip=src_ip,
    )
    db.add(event)
    await db.commit()
    return event


async def test_no_src_ip_correlates_to_zero():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        assert await count_recent_events_from_ip(db, None, before=now) == 0


async def test_counts_events_from_same_ip_within_window():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        for _ in range(4):
            await _make_event(db, src_ip="1.2.3.4", received_at=now)
        count = await count_recent_events_from_ip(db, "1.2.3.4", before=now)
        assert count == 4


async def test_ignores_events_outside_window():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        await _make_event(db, src_ip="1.2.3.4", received_at=now)
        await _make_event(
            db, src_ip="1.2.3.4", received_at=now - timedelta(minutes=CORRELATION_WINDOW_MINUTES + 5)
        )
        count = await count_recent_events_from_ip(db, "1.2.3.4", before=now)
        assert count == 1


async def test_ignores_events_from_a_different_ip():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        await _make_event(db, src_ip="1.2.3.4", received_at=now)
        await _make_event(db, src_ip="9.9.9.9", received_at=now)
        count = await count_recent_events_from_ip(db, "1.2.3.4", before=now)
        assert count == 1
