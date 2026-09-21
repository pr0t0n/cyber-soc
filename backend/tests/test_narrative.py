"""Síntese operacional (app/services/narrative.py) — painel N3: incidente
como história, linha do tempo real do ambiente, e comparação de tráfego
contra o próprio histórico."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Event, Incident, LearnedPattern
from app.services import narrative

_NOW = datetime(2026, 6, 25, 12, 0, tzinfo=timezone.utc)


async def test_incident_narrative_aggregates_fused_events_and_glpi_status():
    async with SessionLocal() as db:
        incident = Incident(
            code="INC-7001", title="Teste", status="em_andamento", severity="alta", risk_score=40,
            created_at=_NOW - timedelta(hours=2), glpi_ticket_id=99, glpi_status_raw=2,
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)

        db.add(Event(
            source="wazuh", type="Port scan", severity="alta", timestamp=_NOW, received_at=_NOW,
            src_ip="172.22.0.5", mitre=["T1595"], matched_skills=["CSOC-002"], incident_id=incident.id,
        ))
        await db.commit()

        items = await narrative.build_incident_narratives(db)
        assert len(items) == 1
        item = items[0]
        assert item["code"] == "INC-7001"
        assert item["src_ips"] == ["172.22.0.5"]
        assert item["techniques"] == ["T1595"]
        assert item["glpi_status_label"] == "Atribuído"
        assert "INC-7001" in item["narrative"]
        assert "T1595" in item["narrative"]


async def test_incident_narrative_excludes_concluded_incidents():
    async with SessionLocal() as db:
        db.add(Incident(code="INC-7002", title="Fechado", status="concluido", severity="baixa"))
        await db.commit()

        items = await narrative.build_incident_narratives(db)
        assert items == []


async def test_activity_timeline_merges_and_sorts_all_three_sources():
    async with SessionLocal() as db:
        db.add(Incident(
            code="INC-7003", title="Recente", status="backlog", severity="alta",
            created_at=_NOW,
        ))
        db.add(LearnedPattern(
            pattern_key="SSHD brute force", confirmations=3, promoted=True,
            last_confirmed_at=_NOW - timedelta(minutes=5),
        ))
        db.add(Event(
            source="wazuh", type="Port scan suspeito", severity="baixa",
            timestamp=_NOW - timedelta(minutes=10), received_at=_NOW - timedelta(minutes=10),
            src_ip="203.0.113.9", rules_engine_status="suspicious",
        ))
        await db.commit()

        items = await narrative.build_activity_timeline(db)
        kinds = [i["kind"] for i in items]
        assert "incident_created" in kinds
        assert "pattern_learned" in kinds
        assert "suspicious_flagged" in kinds
        # Mais recente primeiro.
        assert items[0]["kind"] == "incident_created"


async def test_traffic_baseline_flags_new_origin_above_baseline():
    # `build_traffic_baseline_overview` usa `datetime.now()` internamente
    # (janela "últimas 24h" de verdade) — não dá pra usar `_NOW` fixo aqui
    # como nos outros testes deste arquivo.
    real_now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        for i in range(6):
            db.add(Event(
                source="wazuh", type="Port scan", severity="baixa",
                timestamp=real_now, received_at=real_now, src_ip="203.0.113.50",
            ))
        await db.commit()

        items = await narrative.build_traffic_baseline_overview(db, top_n=5)
        assert len(items) == 1
        assert items[0]["src_ip"] == "203.0.113.50"
        assert items[0]["events_24h"] == 6
        assert items[0]["first_seen_this_window"] is True
        assert items[0]["is_above_baseline"] is True
