"""O motor de regras real (Supervisor LangGraph + MCP + Ollama) é caro e
precisa de rede/LLM — aqui ele é monkeypatched para simular um veredito
determinístico e testar só a lógica de negócio (abrir Incidente, herdar tag,
mudar status). O motor em si (parsing de JSON, grafo, prompts) tem testes
próprios em test_rules_engine.py."""
from app.services import rules_engine


def _mock_matched(skills=("T1110",)):
    async def _fake(event: dict) -> dict:
        return {"matched": True, "matched_skills": list(skills), "summary": "Padrão de força bruta reconhecido.", "groups": {}}
    return _fake


def _mock_no_match():
    async def _fake(event: dict) -> dict:
        return {"matched": False, "matched_skills": [], "summary": "Nenhuma skill correspondente.", "groups": {}}
    return _fake


async def test_rules_engine_match_opens_incident(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())
    created = await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
    })
    event_id = created.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    r = await client.get("/api/incidents", headers=auth_headers)
    assert r.status_code == 200
    incidents = r.json()
    assert len(incidents) == 1
    assert incidents[0]["status"] == "backlog"
    assert incidents[0]["code"] == "INC-0001"

    event = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert event["status"] == "new"  # status operacional do evento é distinto do veredito da IA


async def test_rules_engine_no_match_does_not_open_incident(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match())
    created = await client.post("/api/ingest/generic", json={"type": "healthcheck", "severity": "info"})
    await rules_engine.run_rules_engine_for_event(created.json()["id"])

    r = await client.get("/api/incidents", headers=auth_headers)
    assert r.json() == []


async def test_update_incident_status(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())
    created = await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 12, "description": "Brute force"},
        "data": {"srcip": "185.220.101.8", "dstport": "3389", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(created.json()["id"])
    incident_id = (await client.get("/api/incidents", headers=auth_headers)).json()[0]["id"]

    r = await client.patch(f"/api/incidents/{incident_id}", headers=auth_headers, json={"status": "em_andamento"})
    assert r.status_code == 200
    assert r.json()["status"] == "em_andamento"

    invalid = await client.patch(f"/api/incidents/{incident_id}", headers=auth_headers, json={"status": "nao-existe"})
    assert invalid.status_code == 400


async def test_incident_inherits_connector_tag(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())
    created_connector = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh VALID", "kind": "siem", "type": "wazuh", "config": {"client_tag": "VALID"},
    })
    token = created_connector.json()["ingest_token"]

    created_event = await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 12, "description": "Brute force"},
        "data": {"srcip": "185.220.101.8", "dstport": "3389", "protocol": "TCP"},
    }, headers={"Authorization": f"Bearer {token}"})
    await rules_engine.run_rules_engine_for_event(created_event.json()["id"])

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert incidents[0]["tag"] == "VALID"

    events = (await client.get("/api/events?tag=VALID", headers=auth_headers)).json()
    assert events["total"] == 1

    filtered_out = (await client.get("/api/events?tag=OUTRO", headers=auth_headers)).json()
    assert filtered_out["total"] == 0
