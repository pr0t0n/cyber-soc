from app.services import rules_engine


async def _ingest_sample(client):
    r = await client.post("/api/ingest/wazuh", json={
        "id": "1", "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    return r.json()["id"]


async def _mock_matched(event: dict, on_progress=None) -> dict:
    return {"matched": True, "matched_skills": ["T1110"], "summary": "Força bruta reconhecida.", "groups": {}}


async def test_summary(client, auth_headers):
    await _ingest_sample(client)
    r = await client.get("/api/dashboard/summary", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["severity_counts"]["critica"] == 1
    assert body["mitre_coverage_pct"] > 0


async def test_eps_and_funnel(client, auth_headers):
    await _ingest_sample(client)
    r = await client.get("/api/dashboard/eps", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] == 1
    assert body["funnel"][0]["stage"] == "eps"
    assert body["funnel"][0]["pct_of_total"] == 100.0


async def test_summary_filters_by_tag(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh VALID", "kind": "siem", "type": "wazuh", "config": {"client_tag": "VALID"},
    })
    token = created.json()["ingest_token"]
    await client.post("/api/ingest/wazuh", json={"rule": {"level": 12}}, headers={"Authorization": f"Bearer {token}"})
    # Fonte diferente (sem conector/token) para não colidir com o gate de token do wazuh.
    await client.post("/api/ingest/generic", json={"type": "outro", "severity": "critica"})

    tagged = (await client.get("/api/dashboard/summary?tag=VALID", headers=auth_headers)).json()
    assert tagged["severity_counts"]["critica"] == 1
    all_events = (await client.get("/api/dashboard/summary", headers=auth_headers)).json()
    assert all_events["severity_counts"]["critica"] == 2


async def test_mitre_heatmap(client, auth_headers):
    await _ingest_sample(client)
    r = await client.get("/api/dashboard/mitre-heatmap", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    tactic = next(t for t in body["tactics"] if t["name"] == "Acesso Inicial")
    cell = next(c for c in tactic["techniques"] if c["id"] == "T1110")
    assert cell["count"] == 1


async def test_connectors_status_empty(client, auth_headers):
    r = await client.get("/api/dashboard/connectors-status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 0


async def test_tickets_status_honest_placeholder(client, auth_headers):
    r = await client.get("/api/dashboard/tickets-status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["summary"]["total"] == 0


async def test_incidents_status_reflects_real_incidents(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client)
    await rules_engine.run_rules_engine_for_event(event_id)  # motor de regras "casou" -> abre incidente em backlog

    r = await client.get("/api/dashboard/incidents-status", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["backlog"] == 1
    assert body["summary"]["total"] == 1
    assert body["recent"][0]["status"] == "backlog"


async def test_risk_heatmap_shape(client, auth_headers):
    # _ingest_sample usa uma data fixa fora da janela de 7 dias do heatmap;
    # aqui usamos "agora" para cair dentro da janela.
    await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
    })
    r = await client.get("/api/dashboard/risk-heatmap", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["grid"]) == 7 and len(body["grid"][0]) == 24
    assert any(v > 0 for row in body["grid"] for v in row)


async def test_world_map_empty_without_geo(client, auth_headers):
    # AUTO_GEO_ON_INGEST=false nos testes -> nenhum evento tem lat/lon.
    await _ingest_sample(client)
    r = await client.get("/api/dashboard/world-map", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["points"] == []


async def test_tags_endpoint_lists_distinct_tags(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh VALID", "kind": "siem", "type": "wazuh", "config": {"client_tag": "VALID"},
    })
    token = created.json()["ingest_token"]
    await client.post("/api/ingest/wazuh", json={"rule": {"level": 1}}, headers={"Authorization": f"Bearer {token}"})

    r = await client.get("/api/dashboard/tags", headers=auth_headers)
    assert r.json()["tags"] == ["VALID"]


async def test_eps_funnel_ends_in_incidents(client, auth_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client)

    before = await client.get("/api/dashboard/eps", headers=auth_headers)
    assert before.json()["pending_analysis"] == 1  # motor de regras ainda não rodou

    await rules_engine.run_rules_engine_for_event(event_id)

    r = await client.get("/api/dashboard/eps", headers=auth_headers)
    body = r.json()
    stages = [f["stage"] for f in body["funnel"]]
    assert stages == ["eps", "rules_engine", "incident"]
    assert body["funnel"][1]["count"] == 1  # motor de regras casou o evento
    assert body["funnel"][-1]["count"] == 1  # e virou 1 incidente
    assert body["pending_analysis"] == 0
