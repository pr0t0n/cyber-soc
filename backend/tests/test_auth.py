async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_bootstrap_admin_login(client):
    r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "admin123"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["role"] == "admin"
    assert body["user"]["email"] == "admin@example.com"


async def test_wrong_password_rejected(client):
    r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "wrong"})
    assert r.status_code == 401


async def test_no_self_registration_endpoint(client):
    # Não existe /api/auth/register nem qualquer rota de auto-cadastro.
    r = await client.post("/api/auth/register", json={})
    assert r.status_code == 404


async def test_only_admin_creates_users(client, auth_headers):
    r = await client.post(
        "/api/auth/users", headers=auth_headers,
        json={"name": "Analista 1", "email": "analista1@example.com", "password": "senha123", "role": "analista"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "analista"

    login = await client.post("/api/auth/login", json={"email": "analista1@example.com", "password": "senha123"})
    assert login.status_code == 200
    analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    forbidden = await client.post(
        "/api/auth/users", headers=analyst_headers,
        json={"name": "Outro", "email": "outro@example.com", "password": "x", "role": "analista"},
    )
    assert forbidden.status_code == 403


async def test_duplicate_email_rejected(client, auth_headers):
    r = await client.post(
        "/api/auth/users", headers=auth_headers,
        json={"name": "Dup", "email": "admin@example.com", "password": "x", "role": "analista"},
    )
    assert r.status_code == 409
