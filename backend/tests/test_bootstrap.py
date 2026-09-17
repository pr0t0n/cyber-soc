"""Um restart do processo da API (deploy, crash, rebuild) perde qualquer
BackgroundTask agendada na memória — sem reagendar no boot, um evento
pending/analyzing fica travado para sempre. _requeue_stuck_events cobre isso."""
import asyncio

from app import bootstrap as bootstrap_module
from app.db import SessionLocal
from app.models import Event


async def _make_event(db, *, status: str) -> int:
    event = Event(
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        source="generic", type="teste", severity="info", rules_engine_status=status,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event.id


async def test_requeue_reschedules_only_pending_and_analyzing(monkeypatch):
    scheduled: list[int] = []

    async def _fake_run(event_id: int) -> None:
        scheduled.append(event_id)

    monkeypatch.setattr(bootstrap_module, "run_rules_engine_for_event", _fake_run)

    async with SessionLocal() as db:
        pending_id = await _make_event(db, status="pending")
        analyzing_id = await _make_event(db, status="analyzing")
        await _make_event(db, status="matched")
        await _make_event(db, status="no_match")
        await _make_event(db, status="informational")

        count = await bootstrap_module._requeue_stuck_events(db)

    assert count == 2
    # asyncio.create_task agenda mas não espera — dá um tick para rodar.
    await asyncio.sleep(0)
    assert sorted(scheduled) == sorted([pending_id, analyzing_id])


async def test_requeue_is_noop_when_nothing_stuck():
    async with SessionLocal() as db:
        await _make_event(db, status="matched")
        count = await bootstrap_module._requeue_stuck_events(db)
    assert count == 0
