"""Esquema real de credenciais/formato de integração (app/services/
connector_schemas.py) e teste de conectividade real para Wazuh/Elastic
(app/api/connectors.py _test_wazuh/_test_elastic) — grounded na documentação
oficial de cada plataforma, não inventado (ver docstrings dos módulos)."""
import httpx

from app.api import connectors as connectors_module


class _FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, get_response=None, post_response=None, raise_error: bool = False):
        self._get_response = get_response
        self._post_response = post_response
        self._raise_error = raise_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        if self._raise_error:
            raise httpx.ConnectError("conexão recusada")
        return self._get_response

    async def post(self, url, **kwargs):
        if self._raise_error:
            raise httpx.ConnectError("conexão recusada")
        return self._post_response


async def test_schemas_endpoint_lists_wazuh_and_elastic_with_real_docs(client, auth_headers):
    r = await client.get("/api/admin/connectors/schemas", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "siem:wazuh" in body
    assert body["siem:wazuh"]["docs_url"].startswith("https://documentation.wazuh.com")
    assert body["siem:wazuh"]["test_supported"] is True
    assert "<integration>" in body["siem:wazuh"]["integration_format"]

    assert "siem:elastic" in body
    assert body["siem:elastic"]["docs_url"].startswith("https://www.elastic.co")


async def test_created_connector_reveals_real_token_in_integration_format_once(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh prod", "kind": "siem", "type": "wazuh",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["ingest_token"] in body["integration_format"]

    listed = (await client.get("/api/admin/connectors", headers=auth_headers)).json()
    row = next(c for c in listed if c["id"] == body["id"])
    assert body["ingest_token"] not in row["integration_format"]


async def test_wazuh_test_connection_skips_when_manager_url_not_configured(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh sem manager_url", "kind": "siem", "type": "wazuh",
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    assert r.json()["status"] == "skipped"


async def test_wazuh_test_connection_ok_with_valid_credentials(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        connectors_module.httpx, "AsyncClient",
        lambda *a, **k: _FakeAsyncClient(post_response=_FakeResponse(200)),
    )
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh prod", "kind": "siem", "type": "wazuh",
        "config": {"manager_url": "https://wazuh.manager:55000", "api_username": "wazuh", "api_password": "senha"},
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    assert r.json()["status"] == "ok"


async def test_wazuh_test_connection_fails_on_bad_credentials(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        connectors_module.httpx, "AsyncClient",
        lambda *a, **k: _FakeAsyncClient(post_response=_FakeResponse(401)),
    )
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh prod", "kind": "siem", "type": "wazuh",
        "config": {"manager_url": "https://wazuh.manager:55000", "api_password": "errada"},
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    assert r.json()["status"] == "fail"


async def test_wazuh_test_connection_reports_unreachable_manager(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        connectors_module.httpx, "AsyncClient",
        lambda *a, **k: _FakeAsyncClient(raise_error=True),
    )
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh prod", "kind": "siem", "type": "wazuh",
        "config": {"manager_url": "https://wazuh.inexistente:55000", "api_password": "x"},
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    assert r.json()["status"] == "fail"
    assert "inacessível" in r.json()["detail"]


async def test_elastic_test_connection_ok_reports_cluster_health(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        connectors_module.httpx, "AsyncClient",
        lambda *a, **k: _FakeAsyncClient(get_response=_FakeResponse(200, {"cluster_name": "prod-es", "status": "green"})),
    )
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Elastic prod", "kind": "siem", "type": "elastic",
        "config": {"es_url": "https://elastic.exemplo:9200", "api_key": "abc"},
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    body = r.json()
    assert body["status"] == "ok"
    assert "prod-es" in body["detail"]


async def test_elastic_test_connection_skips_when_url_not_configured(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Elastic sem url", "kind": "siem", "type": "elastic",
    })
    cid = created.json()["id"]
    r = await client.post(f"/api/admin/connectors/{cid}/test", headers=auth_headers)
    assert r.json()["status"] == "skipped"
