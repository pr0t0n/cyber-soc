"""Um restart do processo da API (deploy, crash, rebuild) perde qualquer
BackgroundTask agendada na memória — sem reagendar no boot, um evento
pending/analyzing fica travado para sempre. _requeue_stuck_events cobre isso."""
import asyncio

from sqlalchemy import select

from app import bootstrap as bootstrap_module
from app.db import SessionLocal
from app.models import Event, Skill


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


async def test_ensure_skills_upserts_stale_content_and_clears_embedding():
    """Conteúdo autoral (correlation.json) muda com o desenvolvimento normal —
    uma skill que existe mas ficou desatualizada precisa se corrigir sozinha
    no próximo boot, não ficar servindo YAML/embedding velhos para sempre."""
    async with SessionLocal() as db:
        row = (
            await db.execute(select(Skill).where(Skill.source == "correlation", Skill.external_id == "CSOC-001"))
        ).scalar_one()
        real_yaml = row.yaml_content
        row.yaml_content = "conteúdo desatualizado de propósito"
        row.embedding = [0.1] * 768
        await db.commit()

        installed, updated = await bootstrap_module._ensure_skills(db)

        assert installed == 0  # nada novo, só o conteúdo mudou
        assert updated >= 1

        await db.refresh(row)
        assert row.yaml_content == real_yaml
        assert row.embedding is None  # precisa reidratar com o conteúdo novo
