async def test_create_connector_masks_secret(client, auth_headers):
    r = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "AbuseIPDB", "kind": "threatintel", "type": "abuseipdb", "config": {"api_key": "segredo"},
    })
    assert r.status_code == 201, r.text
    assert r.json()["config"]["api_key"] == "••••••"


async def test_invalid_kind_rejected(client, auth_headers):
    r = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "X", "kind": "nao-existe", "type": "x",
    })
    assert r.status_code == 400


async def test_analyst_cannot_manage_connectors(client, auth_headers):
    await client.post(
        "/api/auth/users", headers=auth_headers,
        json={"name": "Analista", "email": "a@example.com", "password": "senha123", "role": "analista"},
    )
    login = await client.post("/api/auth/login", json={"email": "a@example.com", "password": "senha123"})
    analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r = await client.get("/api/admin/connectors", headers=analyst_headers)
    assert r.status_code == 403


async def test_update_preserves_unset_secret(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "AbuseIPDB", "kind": "threatintel", "type": "abuseipdb", "config": {"api_key": "segredo"},
    })
    cid = created.json()["id"]
    patched = await client.patch(f"/api/admin/connectors/{cid}", headers=auth_headers, json={
        "config": {"api_key": "••••••", "note": "atualizado"},
    })
    assert patched.status_code == 200
    assert patched.json()["config"]["note"] == "atualizado"

    from app.db import SessionLocal
    from app.models import Connector
    async with SessionLocal() as db:
        row = await db.get(Connector, cid)
        assert row.config["api_key"] == "segredo"


async def test_delete_connector(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Webhook", "kind": "notification", "type": "webhook", "config": {},
    })
    cid = created.json()["id"]
    r = await client.delete(f"/api/admin/connectors/{cid}", headers=auth_headers)
    assert r.status_code == 204
    listed = await client.get("/api/admin/connectors", headers=auth_headers)
    assert all(c["id"] != cid for c in listed.json())
