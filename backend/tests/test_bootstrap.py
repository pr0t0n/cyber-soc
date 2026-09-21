"""Um restart do processo da API (deploy, crash, rebuild) perde qualquer
BackgroundTask agendada na memória — sem reagendar no boot, um evento
pending/analyzing fica travado para sempre. _requeue_stuck_events cobre isso."""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import bootstrap as bootstrap_module
from app.db import SessionLocal
from app.models import Event, Skill


async def _make_event(db, *, status: str, received_at: datetime | None = None) -> int:
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source="generic", type="teste", severity="info", rules_engine_status=status,
    )
    if received_at is not None:
        event.received_at = received_at
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
            await db.execute(select(Skill).where(Skill.source == "attack_defend", Skill.external_id == "CSOC-001"))
        ).scalar_one()
        real_yaml = row.yaml_content
        row.yaml_content = "conteúdo desatualizado de propósito"
        row.embedding = [0.1] * 768
        await db.commit()

        installed, updated, removed = await bootstrap_module._ensure_skills(db)

        assert installed == 0  # nada novo, só o conteúdo mudou
        assert updated >= 1
        assert removed == 0

        await db.refresh(row)
        assert row.yaml_content == real_yaml


async def test_sweep_orphaned_events_reschedules_only_old_stuck_events(monkeypatch):
    """Achado real: mesmo com o teto de tempo + handler de exceção em
    run_rules_engine_for_event, a própria escrita de limpeza pode falhar
    silenciosamente sob contenção de pico, deixando o evento "analyzing" para
    sempre sem nenhum erro visível (5-7 de ~80 eventos num teste de carga real).
    A varredura periódica é a rede de segurança independente disso: qualquer
    pending/analyzing mais velho que o teto (com folga) é garantidamente órfão,
    nunca trabalho real em andamento, e pode ser reagendado com segurança."""
    scheduled: list[int] = []

    async def _fake_run(event_id: int) -> None:
        scheduled.append(event_id)
        async with SessionLocal() as db:
            event = await db.get(Event, event_id)
            event.rules_engine_status = "no_match"
            await db.commit()

    monkeypatch.setattr(bootstrap_module, "run_rules_engine_for_event", _fake_run)

    now = datetime.now(timezone.utc)
    old_enough = now - timedelta(minutes=bootstrap_module._ORPHAN_THRESHOLD_MINUTES + 1)
    too_recent = now - timedelta(minutes=1)

    async with SessionLocal() as db:
        orphan_id = await _make_event(db, status="analyzing", received_at=old_enough)
        await _make_event(db, status="pending", received_at=too_recent)
        await _make_event(db, status="matched", received_at=old_enough)

    # `asyncio` é um módulo singleton — mockar `bootstrap_module.asyncio.sleep`
    # mockaria `asyncio.sleep` globalmente para o processo de teste inteiro.
    # Em vez disso, zera o intervalo real e deixa o loop rodar de verdade por
    # uma janela curta, cancelando via timeout.
    monkeypatch.setattr(bootstrap_module, "_ORPHAN_SWEEP_INTERVAL_SECONDS", 0)

    try:
        await asyncio.wait_for(bootstrap_module._sweep_orphaned_events_forever(), timeout=0.2)
    except asyncio.TimeoutError:
        pass

    # com intervalo 0 o loop pode encontrar o mesmo órfão mais de uma vez antes
    # do reagendamento anterior confirmar seu próprio status — inofensivo em
    # produção (reagendar de novo é idempotente), então o que importa aqui é
    # que só o órfão certo foi disparado, e que o evento saiu do estado travado.
    assert set(scheduled) == {orphan_id}

    async with SessionLocal() as db:
        resolved = await db.get(Event, orphan_id)
        assert resolved.rules_engine_status == "no_match"


async def test_ensure_skills_removes_orphaned_rows_no_longer_in_catalog():
    """Achado real: quando a organização do catálogo muda (ex.: fontes
    fragmentadas viraram skills unificadas por técnica), uma linha cuja chave
    (source, external_id) não existe mais no catálogo gerado ficava órfã na
    tabela para sempre — aparecendo na página Regras junto do catálogo novo,
    nunca removida por um upsert que só insere/atualiza."""
    async with SessionLocal() as db:
        db.add(Skill(
            source="suricata", external_id="9999999", name="Assinatura órfã de teste",
            category="teste", yaml_content="skill: teste", search_text="assinatura órfã de teste",
        ))
        await db.commit()

        installed, updated, removed = await bootstrap_module._ensure_skills(db)

        assert removed >= 1
        remaining = (
            await db.execute(select(Skill).where(Skill.source == "suricata", Skill.external_id == "9999999"))
        ).scalar_one_or_none()
        assert remaining is None
