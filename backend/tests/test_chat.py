async def test_chat_degrades_gracefully_without_llm(client, auth_headers):
    r = await client.post("/api/chat", headers=auth_headers, json={"message": "algo suspeito?"})
    assert r.status_code == 200
    body = r.json()
    assert body["degraded"] is True
    assert "IA indisponível" in body["answer"]


async def test_chat_requires_auth(client):
    r = await client.post("/api/chat", json={"message": "oi"})
    assert r.status_code == 401


async def test_chat_hydrates_context_with_ip_specific_events(client, auth_headers, ingest_headers):
    """O Copilot precisa reconhecer um IP na pergunta e trazer o histórico real
    daquele IP (não só a lista genérica dos últimos eventos) — é o que faz
    "o que é o IP X" ter uma resposta útil em vez de genérica."""
    await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    r = await client.post("/api/chat", headers=auth_headers, json={"message": "o que é o IP 185.220.101.8?"})
    assert r.status_code == 200
    answer = r.json()["answer"]
    assert "185.220.101.8" in answer
    assert "SSHD brute force" in answer
