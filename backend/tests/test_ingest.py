async def test_ingest_wazuh_normalizes_and_scores(client, auth_headers):
    r = await client.post("/api/ingest/wazuh", json={
        "id": "1700000000.1",
        "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "agent": {"name": "srv-01"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
        "full_log": "Failed password for root...",
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["severity"] == "critica"
    assert body["risk_score"] >= 35  # porta 3389 (RDP exposto) já pontua

    listed = await client.get("/api/events", headers=auth_headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    item = listed.json()["items"][0]
    assert item["mitre"] == ["T1110"]
    assert item["dst_port"] == "3389"


async def test_ingest_wazuh_extracts_hit_count_and_rule_ref(client, auth_headers):
    """Gap corrigido: uma alegação de 'brute force' sem contagem de tentativas
    não é sustentável — `rule.firedtimes` (contador nativo do Wazuh para
    regras de frequência) precisa sobreviver à ingestão, e a severidade
    precisa vir acompanhada da regra de origem que a gerou."""
    r = await client.post("/api/ingest/wazuh", json={
        "id": "1700000000.2",
        "rule": {"id": "5720", "level": 12, "description": "SSHD brute force", "firedtimes": 9},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    assert r.status_code == 201, r.text
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["hit_count"] == 9
    assert "5720" in detail["rule_ref"] and "nível 12" in detail["rule_ref"]


async def test_ingest_wazuh_without_firedtimes_leaves_hit_count_null(client, auth_headers):
    r = await client.post("/api/ingest/wazuh", json={
        "rule": {"id": "1", "level": 3, "description": "Evento comum"},
        "data": {"srcip": "10.0.0.9"},
    })
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["hit_count"] is None


async def test_ingest_generic_low_risk_traffic(client, auth_headers):
    r = await client.post("/api/ingest/generic", json={
        "type": "HTTP request", "severity": "info",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": "443", "protocol": "TCP",
    })
    assert r.status_code == 201, r.text
    assert r.json()["risk_score"] == 0


async def test_ingest_unsupported_source_rejected(client):
    r = await client.post("/api/ingest/nope", json={})
    assert r.status_code == 400


async def test_ingest_requires_token_once_siem_connector_configured(client, auth_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh prod", "kind": "siem", "type": "wazuh",
    })
    assert created.status_code == 201, created.text
    token = created.json()["ingest_token"]
    assert token

    unauthorized = await client.post("/api/ingest/wazuh", json={"rule": {"level": 1}})
    assert unauthorized.status_code == 401

    wrong = await client.post("/api/ingest/wazuh", json={"rule": {"level": 1}}, headers={"Authorization": "Bearer errado"})
    assert wrong.status_code == 401

    ok = await client.post("/api/ingest/wazuh", json={"rule": {"level": 1}}, headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 201, ok.text

    # Fonte diferente sem conector configurado continua aberta (modo dev).
    still_open = await client.post("/api/ingest/generic", json={"type": "teste", "severity": "info"})
    assert still_open.status_code == 201


async def test_event_detail(client, auth_headers):
    created = await client.post("/api/ingest/generic", json={"type": "Teste", "severity": "media"})
    event_id = created.json()["id"]
    detail = await client.get(f"/api/events/{event_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["id"] == event_id
    assert "enrichment" in detail.json()


async def test_event_not_found(client, auth_headers):
    r = await client.get("/api/events/999999", headers=auth_headers)
    assert r.status_code == 404


async def test_raw_events_lists_source_data_untouched_by_ai(client, auth_headers):
    await client.post("/api/ingest/wazuh", json={
        "rule": {"id": "5720", "level": 12, "description": "SSHD brute force", "groups": ["authentication_failed"]},
        "data": {"srcip": "185.220.101.8"},
        "full_log": "Failed password for root from 185.220.101.8",
    })
    r = await client.get("/api/events/raw", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["rule_id"] == "5720"
    assert item["rule_level"] == 12
    assert item["rule_groups"] == ["authentication_failed"]
    assert "Failed password" in item["full_log"]


async def test_raw_events_full_text_search_matches_raw_json(client, auth_headers):
    await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 5, "description": "SCA summary"},
        "data": {"srcip": "1.2.3.4"},
    })
    await client.post("/api/ingest/generic", json={"type": "Outro evento", "severity": "info"})

    found = await client.get("/api/events/raw?q=1.2.3.4", headers=auth_headers)
    assert found.json()["total"] == 1

    not_found = await client.get("/api/events/raw?q=9.9.9.9", headers=auth_headers)
    assert not_found.json()["total"] == 0
