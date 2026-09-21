"""Sincronização de status com o GLPI (app/services/notify.py) — pedido
real: o status do incidente na plataforma não pode ser uma lista suspensa
editável à parte, tem que refletir o que o ticket diz no GLPI."""
import httpx

from app.db import SessionLocal
from app.models import Connector, Incident
from app.services import notify


class _FakeResp:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


def _fake_glpi_client(ticket_statuses: dict[int, int]):
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, **kwargs):
            if url.endswith("/initSession"):
                return _FakeResp(json_data={"session_token": "sess123"})
            ticket_id = int(url.rsplit("/", 1)[-1])
            if ticket_id not in ticket_statuses:
                return _FakeResp(status_code=404)
            return _FakeResp(json_data={"id": ticket_id, "status": ticket_statuses[ticket_id]})

    return _Client()


async def _add_glpi_connector(db):
    connector = Connector(
        name="GLPI", kind="notification", type="glpi", status="enabled",
        config={"base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1", "severities": ["alta"]},
    )
    db.add(connector)
    await db.commit()
    return connector


async def _add_incident(db, *, glpi_ticket_id: int, status: str = "backlog") -> Incident:
    incident = Incident(code=f"INC-{glpi_ticket_id:04d}", title="Teste", status=status, severity="alta", glpi_ticket_id=glpi_ticket_id)
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


async def test_sync_updates_incident_status_from_real_glpi_ticket_status(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _fake_glpi_client({10: 5}))  # 5 = Solved
    async with SessionLocal() as db:
        await _add_glpi_connector(db)
        incident = await _add_incident(db, glpi_ticket_id=10, status="backlog")

        result = await notify.sync_all_glpi_statuses(db)
        assert result == {"synced": 1, "failed": 0}

        await db.refresh(incident)
        assert incident.status == "concluido"
        assert incident.glpi_status_raw == 5
        assert incident.glpi_synced_at is not None


async def test_sync_maps_assigned_and_planned_to_em_andamento(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _fake_glpi_client({11: 2, 12: 3}))
    async with SessionLocal() as db:
        await _add_glpi_connector(db)
        inc_assigned = await _add_incident(db, glpi_ticket_id=11, status="backlog")
        inc_planned = await _add_incident(db, glpi_ticket_id=12, status="backlog")

        await notify.sync_all_glpi_statuses(db)

        await db.refresh(inc_assigned)
        await db.refresh(inc_planned)
        assert inc_assigned.status == "em_andamento"
        assert inc_planned.status == "em_andamento"


async def test_sync_skips_incidents_without_glpi_ticket(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _fake_glpi_client({}))
    async with SessionLocal() as db:
        await _add_glpi_connector(db)
        no_ticket = Incident(code="INC-9999", title="Sem GLPI", status="backlog", severity="media")
        db.add(no_ticket)
        await db.commit()

        result = await notify.sync_all_glpi_statuses(db)
        assert result == {"synced": 0, "failed": 0}


async def test_sync_counts_failures_without_raising_when_ticket_missing(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _fake_glpi_client({}))  # ticket 20 não existe -> 404
    async with SessionLocal() as db:
        await _add_glpi_connector(db)
        await _add_incident(db, glpi_ticket_id=20, status="backlog")

        result = await notify.sync_all_glpi_statuses(db)
        assert result == {"synced": 0, "failed": 1}


async def test_sync_returns_zero_without_a_glpi_connector():
    async with SessionLocal() as db:
        result = await notify.sync_all_glpi_statuses(db)
        assert result == {"synced": 0, "failed": 0}
