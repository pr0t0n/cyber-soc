"""ASM mínimo (app/services/asm.py) — reaproveita o Shodan já integrado em
threat_intel.py, só que chamado PROATIVAMENTE contra os IPs públicos de
destino já observados nos eventos, não reativamente contra o atacante."""
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Connector, Event, IocCache
from app.services import asm

_NOW = datetime.now(timezone.utc)
_PUBLIC_IP = "185.220.101.8"  # mesma faixa usada no resto do projeto como IP público de exemplo
_PRIVATE_IP = "10.0.0.5"


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


async def _add_shodan_connector(api_key: str = "segredo") -> None:
    async with SessionLocal() as db:
        db.add(Connector(name="Shodan", kind="threatintel", type="shodan", status="enabled", config={"api_key": api_key}))
        await db.commit()


async def test_no_exposed_ips_when_only_private_dst_ip_observed():
    await _add_event(dst_ip=_PRIVATE_IP)

    async with SessionLocal() as db:
        result = await asm.list_exposed_assets(db)
    assert result["items"] == []


async def test_public_dst_ip_is_listed_even_without_shodan_connector():
    await _add_event(dst_ip=_PUBLIC_IP)

    async with SessionLocal() as db:
        result = await asm.list_exposed_assets(db)
    assert result["shodan_configured"] is False
    assert len(result["items"]) == 1
    assert result["items"][0]["ip"] == _PUBLIC_IP
    assert result["items"][0]["status"] == "sem_provedor_configurado"


async def test_events_older_than_window_are_excluded():
    stale = _NOW - timedelta(days=45)
    await _add_event(dst_ip=_PUBLIC_IP, received_at=stale)

    async with SessionLocal() as db:
        result = await asm.list_exposed_assets(db, window_days=30)
    assert result["items"] == []


async def test_refresh_is_a_noop_without_a_shodan_connector():
    await _add_event(dst_ip=_PUBLIC_IP)

    async with SessionLocal() as db:
        checked = await asm.refresh_exposed_assets(db)
    assert checked == 0


async def test_refresh_queries_shodan_for_each_public_ip_and_caches_the_result(monkeypatch):
    await _add_event(dst_ip=_PUBLIC_IP)
    await _add_shodan_connector()

    calls = []

    async def _mock_query_shodan(api_key, ip):
        calls.append(ip)
        return {"provider": "shodan", "status": "ok", "found": True, "ports": [22, 443], "org": "Exemplo", "tags": ["cloud"], "vulns": []}

    monkeypatch.setattr(asm.threat_intel, "query_shodan", _mock_query_shodan)

    async with SessionLocal() as db:
        checked = await asm.refresh_exposed_assets(db)
    assert checked == 1
    assert calls == [_PUBLIC_IP]

    async with SessionLocal() as db:
        result = await asm.list_exposed_assets(db)
    item = result["items"][0]
    assert result["shodan_configured"] is True
    assert item["status"] == "ok"
    assert item["found"] is True
    assert item["ports"] == [22, 443]
    assert item["org"] == "Exemplo"
    assert item["checked_at"] is not None


async def test_refresh_skips_ips_with_still_fresh_cache(monkeypatch):
    await _add_event(dst_ip=_PUBLIC_IP)
    await _add_shodan_connector()

    calls = []

    async def _mock_query_shodan(api_key, ip):
        calls.append(ip)
        return {"provider": "shodan", "status": "ok", "found": True, "ports": [22], "org": None, "tags": [], "vulns": []}

    monkeypatch.setattr(asm.threat_intel, "query_shodan", _mock_query_shodan)

    async with SessionLocal() as db:
        await asm.refresh_exposed_assets(db)
        checked_again = await asm.refresh_exposed_assets(db)
    assert len(calls) == 1  # segunda chamada não repetiu a consulta
    assert checked_again == 0


async def test_asm_cache_uses_its_own_indicator_type_not_shared_with_reactive_lookup():
    """`IocCache` já guarda reputação REATIVA do `src_ip` (indicator_type
    "ip") — o cache proativo do ASM não pode se misturar com isso, senão um
    IP que já é "atacante" conhecido vazaria como resultado de ASM (ou
    vice-versa) sem nenhuma consulta real ao Shodan ter acontecido pra esse
    propósito."""
    async with SessionLocal() as db:
        db.add(IocCache(
            indicator=_PUBLIC_IP, indicator_type="ip",
            result={"provider": "shodan", "status": "ok", "found": True, "ports": [9999], "tags": [], "vulns": []},
            checked_at=datetime.now(timezone.utc),
        ))
        await db.commit()

    await _add_event(dst_ip=_PUBLIC_IP)

    async with SessionLocal() as db:
        result = await asm.list_exposed_assets(db)
    assert result["items"][0]["status"] == "sem_provedor_configurado"
    assert result["items"][0]["ports"] == []
