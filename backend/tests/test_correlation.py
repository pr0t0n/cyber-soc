"""Um analista de SOC nunca julga um evento isolado — várias ocorrências da
mesma origem em poucos minutos é sinal por si só (varredura, força bruta),
mesmo que nenhum evento individual pareça grave sozinho."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Event, Incident
from app.services.correlation import (
    CORRELATION_WINDOW_MINUTES,
    MULTI_ORIGIN_TARGET_WINDOW_MINUTES,
    count_distinct_origins_targeting,
    count_recent_events_from_ip,
    find_technique_matches_in_other_open_incidents,
)


async def _make_event(db, *, src_ip: str, received_at: datetime, **kwargs) -> Event:
    defaults = dict(
        timestamp=received_at, received_at=received_at,
        source="generic", type="teste", severity="info", src_ip=src_ip,
    )
    defaults.update(kwargs)
    event = Event(**defaults)
    db.add(event)
    await db.commit()
    return event


async def _make_open_incident(db, *, code: str) -> int:
    incident = Incident(code=code, title="Teste", status="backlog", severity="alta", event_id=None)
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident.id


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


async def test_technique_match_finds_same_technique_confirmed_by_a_different_origin():
    """Segundo hop de correlação: mesma técnica MITRE CONFIRMADA em outro
    incidente aberto, de origem diferente, é sinal de campanha."""
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident_id = await _make_open_incident(db, code="INC-1001")
        await _make_event(
            db, src_ip="9.9.9.9", received_at=now, mitre=["T1110"],
            rules_engine_status="matched", incident_id=incident_id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now,
        )
        assert len(matches) == 1
        code, src_ip, techniques = matches[0]
        assert code == "INC-1001"
        assert src_ip == "9.9.9.9"
        assert techniques == "T1110"


async def test_technique_match_ignores_the_same_origin():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident_id = await _make_open_incident(db, code="INC-1002")
        await _make_event(
            db, src_ip="1.2.3.4", received_at=now, mitre=["T1110"],
            rules_engine_status="matched", incident_id=incident_id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now,
        )
        assert matches == []


async def test_technique_match_ignores_unconfirmed_events():
    """Uma técnica MITRE crua (da própria fonte, nunca confirmada pela
    análise) em outro incidente não conta — vira ruído."""
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident_id = await _make_open_incident(db, code="INC-1003")
        await _make_event(
            db, src_ip="9.9.9.9", received_at=now, mitre=["T1110"],
            rules_engine_status="no_match", incident_id=incident_id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now,
        )
        assert matches == []


async def test_technique_match_ignores_incidents_already_concluded():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident = Incident(code="INC-1004", title="Teste", status="concluido", severity="alta", event_id=None)
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        await _make_event(
            db, src_ip="9.9.9.9", received_at=now, mitre=["T1110"],
            rules_engine_status="matched", incident_id=incident.id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now,
        )
        assert matches == []


async def test_technique_match_ignores_different_techniques():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident_id = await _make_open_incident(db, code="INC-1005")
        await _make_event(
            db, src_ip="9.9.9.9", received_at=now, mitre=["T1595"],
            rules_engine_status="matched", incident_id=incident_id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now,
        )
        assert matches == []


async def test_technique_match_respects_the_lookback_window():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        incident_id = await _make_open_incident(db, code="INC-1006")
        await _make_event(
            db, src_ip="9.9.9.9", received_at=now - timedelta(days=8), mitre=["T1110"],
            rules_engine_status="matched", incident_id=incident_id,
        )
        matches = await find_technique_matches_in_other_open_incidents(
            db, ["T1110"], exclude_src_ip="1.2.3.4", before=now, window_days=7,
        )
        assert matches == []


async def test_no_mitre_never_matches_anything():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        matches = await find_technique_matches_in_other_open_incidents(db, [], exclude_src_ip=None, before=now)
        assert matches == []


async def test_multiple_origins_targeting_the_same_destination_are_counted():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        await _make_event(db, src_ip="1.1.1.1", received_at=now, dst_ip="10.0.0.5")
        await _make_event(db, src_ip="2.2.2.2", received_at=now, dst_ip="10.0.0.5")
        await _make_event(db, src_ip="3.3.3.3", received_at=now, dst_ip="10.0.0.5")
        count = await count_distinct_origins_targeting(db, "10.0.0.5", exclude_src_ip="1.1.1.1", before=now)
        assert count == 2


async def test_single_origin_targeting_a_destination_counts_as_zero_other_origins():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        await _make_event(db, src_ip="1.1.1.1", received_at=now, dst_ip="10.0.0.5")
        count = await count_distinct_origins_targeting(db, "10.0.0.5", exclude_src_ip="1.1.1.1", before=now)
        assert count == 0


async def test_multi_origin_targeting_respects_its_own_window():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        await _make_event(db, src_ip="1.1.1.1", received_at=now, dst_ip="10.0.0.5")
        await _make_event(
            db, src_ip="2.2.2.2", dst_ip="10.0.0.5",
            received_at=now - timedelta(minutes=MULTI_ORIGIN_TARGET_WINDOW_MINUTES + 5),
        )
        count = await count_distinct_origins_targeting(db, "10.0.0.5", exclude_src_ip="1.1.1.1", before=now)
        assert count == 0


async def test_no_dst_ip_counts_as_zero_other_origins():
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        count = await count_distinct_origins_targeting(db, None, exclude_src_ip="1.1.1.1", before=now)
        assert count == 0
