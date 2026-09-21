"""Registro de ativos derivado do próprio SIEM (app/services/asset_risk.py) —
sem CMDB externo: cada hostname/IP observado vira risco a partir do
histórico real já processado (confirmações, diversidade de técnica,
incidente aberto)."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Event, Incident
from app.services.asset_risk import compute_asset_risk

_NOW = datetime.now(timezone.utc)


async def _add_event(**kwargs) -> Event:
    defaults = dict(
        timestamp=_NOW, received_at=_NOW, source="wazuh", type="Teste", severity="media",
        rules_engine_status="no_match",
    )
    defaults.update(kwargs)
    async with SessionLocal() as db:
        event = Event(**defaults)
        db.add(event)
        await db.commit()
        await db.refresh(event)
        return event


async def test_no_assets_when_no_events():
    async with SessionLocal() as db:
        assert await compute_asset_risk(db) == []


async def test_hostname_takes_priority_over_ip_identity():
    await _add_event(agent_hostname="web-prod-01", src_ip="203.0.113.5", dst_ip="10.0.0.5")

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    assert len(items) == 1
    assert items[0]["kind"] == "hostname"
    assert items[0]["identifier"] == "web-prod-01"
    assert set(items[0]["ips"]) == {"203.0.113.5", "10.0.0.5"}


async def test_public_ip_is_never_treated_as_our_asset():
    """Achado de design: um IP público é o ATACANTE (já coberto por
    AbuseIPDB/Shodan), nunca um ativo nosso — sem hostname do agente, só o
    lado PRIVADO do tráfego deveria contar. `185.220.101.8` (mesma faixa já
    usada nos outros testes do projeto como IP público real de exemplo) —
    faixas de documentação como 203.0.113.0/24 (RFC 5737) NÃO servem aqui:
    o módulo `ipaddress` do Python as marca como `is_private=True`."""
    await _add_event(src_ip="185.220.101.8", dst_ip="10.0.0.5")  # sem agent_hostname

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    assert len(items) == 1
    assert items[0]["kind"] == "ip"
    assert items[0]["identifier"] == "10.0.0.5"


async def test_internal_to_internal_event_contributes_to_both_sides():
    await _add_event(src_ip="10.0.0.7", dst_ip="10.0.0.5")  # movimento lateral, sem hostname

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    identifiers = {i["identifier"] for i in items}
    assert identifiers == {"10.0.0.7", "10.0.0.5"}


async def test_risk_score_rewards_confirmations_technique_diversity_and_open_incident():
    async with SessionLocal() as db:
        incident = Incident(code="INC-9001", title="Teste", status="backlog", severity="alta", event_id=None)
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        open_incident_id = incident.id

    quiet = await _add_event(agent_hostname="quiet-host", severity="baixa", rules_engine_status="no_match")
    loud = await _add_event(
        agent_hostname="loud-host", severity="critica", rules_engine_status="matched",
        mitre=["T1110", "T1595"], incident_id=open_incident_id,
    )

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    by_id = {i["identifier"]: i for i in items}
    assert by_id["loud-host"]["risk_score"] > by_id["quiet-host"]["risk_score"]
    assert by_id["loud-host"]["confirmed_count"] == 1
    assert by_id["loud-host"]["has_open_incident"] is True
    assert set(by_id["loud-host"]["techniques"]) == {"T1110", "T1595"}
    assert quiet.id and loud.id  # eventos criados de fato


async def test_events_older_than_window_are_excluded():
    stale = _NOW - timedelta(days=45)
    await _add_event(agent_hostname="ancient-host", received_at=stale)

    async with SessionLocal() as db:
        items = await compute_asset_risk(db, window_days=30)
    assert items == []


async def test_tag_filters_assets_to_the_matching_client():
    await _add_event(agent_hostname="valid-host", tag="VALID")
    await _add_event(agent_hostname="other-host", tag="OUTRO")

    async with SessionLocal() as db:
        items = await compute_asset_risk(db, tag="VALID")
    assert [i["identifier"] for i in items] == ["valid-host"]


async def test_attack_types_break_down_events_by_mitre_tactic_not_raw_technique_id():
    """Achado real (pedido explícito): um analista não lê "T1110" — lê "Força
    Bruta" ou o nome da tática. `attack_types` categoriza pela mesma lógica
    já usada em Attack Vector (technique_tactic_pt), ordenado do mais pro
    menos frequente."""
    await _add_event(agent_hostname="multi-attack-host", mitre=["T1110"])  # Acesso a Credenciais
    await _add_event(agent_hostname="multi-attack-host", mitre=["T1110"])  # de novo, mesma tática
    await _add_event(agent_hostname="multi-attack-host", mitre=["T1595"])  # Reconhecimento
    await _add_event(agent_hostname="multi-attack-host", mitre=[])         # sem técnica

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    asset = items[0]
    assert asset["identifier"] == "multi-attack-host"
    types = asset["attack_types"]
    assert list(types.items())[0][1] == 2  # tática mais frequente vem primeiro
    assert "Sem técnica MITRE" in types
    assert sum(types.values()) == 4


async def test_first_seen_and_last_seen_track_the_real_event_window():
    older = _NOW - timedelta(days=5)
    newer = _NOW
    await _add_event(agent_hostname="tracked-host", received_at=older)
    await _add_event(agent_hostname="tracked-host", received_at=newer)

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    asset = items[0]
    # SQLite (banco de teste) não guarda fuso — compara só a parte naive,
    # em produção (Postgres, timestamptz) o valor já vem com fuso.
    assert asset["first_seen_at"].split("+")[0] == older.isoformat().split("+")[0]
    assert asset["last_seen_at"].split("+")[0] == newer.isoformat().split("+")[0]
    assert asset["first_seen_at"] < asset["last_seen_at"]


async def test_results_are_sorted_by_event_volume_first_pedido_real():
    """Pedido real: "os ativos que mais receberam informações" — volume vem
    antes de risco na ordenação padrão, não o contrário (um ativo com 1
    evento gravíssimo não deveria aparecer antes de um com 5 eventos leves)."""
    await _add_event(agent_hostname="low-risk-high-volume", severity="info")
    await _add_event(agent_hostname="low-risk-high-volume", severity="info")
    await _add_event(agent_hostname="low-risk-high-volume", severity="info")
    await _add_event(agent_hostname="high-risk-low-volume", severity="critica", rules_engine_status="matched", mitre=["T1110"])

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    assert items[0]["identifier"] == "low-risk-high-volume"
    assert items[0]["event_count"] == 3
    assert items[1]["identifier"] == "high-risk-low-volume"
    assert items[1]["risk_score"] > items[0]["risk_score"]  # risco maior, mas menos volume -> vem depois


async def test_score_never_exceeds_100_even_with_extreme_signals():
    async with SessionLocal() as db:
        incident = Incident(code="INC-9002", title="Teste", status="backlog", severity="critica", event_id=None)
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        open_incident_id = incident.id

    for _ in range(10):
        await _add_event(
            agent_hostname="under-siege", severity="critica", rules_engine_status="matched",
            mitre=[f"T{i}" for i in range(10)], incident_id=open_incident_id,
        )

    async with SessionLocal() as db:
        items = await compute_asset_risk(db)
    assert items[0]["risk_score"] == 100
