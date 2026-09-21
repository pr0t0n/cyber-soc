async def test_ingest_wazuh_normalizes_and_scores(client, auth_headers, ingest_headers):
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
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


async def test_ingest_wazuh_extracts_hit_count_and_rule_ref(client, auth_headers, ingest_headers):
    """Gap corrigido: uma alegação de 'brute force' sem contagem de tentativas
    não é sustentável — `rule.firedtimes` (contador nativo do Wazuh para
    regras de frequência) precisa sobreviver à ingestão, e a severidade
    precisa vir acompanhada da regra de origem que a gerou."""
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "id": "1700000000.2",
        "rule": {"id": "5720", "level": 12, "description": "SSHD brute force", "firedtimes": 9},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    assert r.status_code == 201, r.text
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["hit_count"] == 9
    assert "5720" in detail["rule_ref"] and "nível 12" in detail["rule_ref"]


async def test_ingest_wazuh_without_firedtimes_leaves_hit_count_null(client, auth_headers, ingest_headers):
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"id": "1", "level": 3, "description": "Evento comum"},
        "data": {"srcip": "10.0.0.9"},
    })
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["hit_count"] is None


async def test_ingest_wazuh_extracts_ip_port_protocol_from_suricata_eve_fields(client, auth_headers, ingest_headers):
    """Gap corrigido: quando a regra casada vem de uma fonte externa decodada
    como JSON puro (Suricata via eve.json, ruleset padrão do próprio Wazuh
    0475-suricata_rules.xml), `data` é o registro original da fonte — com
    `src_ip`/`dest_ip`/`src_port`/`dest_port`/`proto`, não os nomes nativos
    do Wazuh (`srcip`/`dstip`/...). Sem o fallback, um alerta de NIDS real
    chegava sem IP/porta/protocolo nenhum."""
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 3, "description": "Suricata: Alert - ET SCAN Nmap Scripting Engine"},
        "data": {
            "src_ip": "203.0.113.9", "src_port": 51000, "dest_ip": "10.0.0.5",
            "dest_port": 445, "proto": "TCP",
        },
    })
    assert r.status_code == 201, r.text
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["src_ip"] == "203.0.113.9"
    assert detail["dst_ip"] == "10.0.0.5"
    assert detail["src_port"] == "51000"
    assert detail["dst_port"] == "445"
    assert detail["protocol"] == "TCP"


async def test_ingest_wazuh_host_telemetry_never_gets_agent_ip_as_dst_ip(client, auth_headers, ingest_headers):
    """Achado real (auditoria de incidentes falsos): telemetria pura de host
    (FIM/"Integrity checksum changed", netstat, sudo, tela bloqueada) nunca
    tem `data.dstip`/`data.dest_ip` de verdade — `agent.ip` (o host que
    RELATOU o evento, não um destino de tráfego) não pode ser usado como
    fallback, senão `is_network_traffic` trata telemetria local como se
    fosse tráfego de rede de verdade."""
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 7, "description": "Integrity checksum changed."},
        "agent": {"id": "003", "name": "host.local", "ip": "172.22.0.2"},
        "data": {},
    })
    assert r.status_code == 201, r.text
    event_id = r.json()["id"]
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["src_ip"] is None
    assert detail["dst_ip"] is None


async def test_ingest_generic_low_risk_traffic(client, auth_headers, ingest_headers):
    r = await client.post("/api/ingest/generic", headers=ingest_headers, json={
        "type": "HTTP request", "severity": "info",
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": "443", "protocol": "TCP",
    })
    assert r.status_code == 201, r.text
    assert r.json()["risk_score"] == 0


async def test_ingest_unsupported_source_rejected(client):
    r = await client.post("/api/ingest/nope", json={})
    assert r.status_code == 400


async def test_ingest_rejects_source_never_integrated(client):
    """Coleta só de plataformas de fato integradas: sem NENHUM conector siem
    habilitado para essa fonte, a ingestão é recusada — não existe mais um
    modo aberto/dev. 'crowdstrike' não tem conector nenhum cadastrado."""
    r = await client.post("/api/ingest/crowdstrike", json={"foo": "bar"})
    assert r.status_code in (400, 403)


async def test_ingest_rejects_missing_or_wrong_token_even_with_connector(client, auth_headers):
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


async def test_event_detail(client, auth_headers, ingest_headers):
    created = await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "Teste", "severity": "media"})
    event_id = created.json()["id"]
    detail = await client.get(f"/api/events/{event_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["id"] == event_id
    assert "enrichment" in detail.json()


async def test_event_not_found(client, auth_headers):
    r = await client.get("/api/events/999999", headers=auth_headers)
    assert r.status_code == 404


async def test_raw_events_lists_source_data_untouched_by_ai(client, auth_headers, ingest_headers):
    await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
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


async def test_raw_events_full_text_search_matches_raw_json(client, auth_headers, ingest_headers):
    await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 5, "description": "SCA summary"},
        "data": {"srcip": "1.2.3.4"},
    })
    await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "Outro evento", "severity": "info"})

    found = await client.get("/api/events/raw?q=1.2.3.4", headers=auth_headers)
    assert found.json()["total"] == 1

    not_found = await client.get("/api/events/raw?q=9.9.9.9", headers=auth_headers)
    assert not_found.json()["total"] == 0
