async def test_chat_degrades_gracefully_without_llm(client, auth_headers):
    r = await client.post("/api/chat", headers=auth_headers, json={"message": "algo suspeito?"})
    assert r.status_code == 200
    body = r.json()
    assert body["degraded"] is True
    assert "IA indisponível" in body["answer"]


async def test_chat_requires_auth(client):
    r = await client.post("/api/chat", json={"message": "oi"})
    assert r.status_code == 401
