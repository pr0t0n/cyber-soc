"""O motor de regras real (Supervisor LangGraph + MCP + Ollama) é caro e
precisa de rede/LLM — aqui ele é monkeypatched para simular um veredito
determinístico e testar só a lógica de negócio (abrir Incidente, herdar tag,
mudar status). O motor em si (parsing de JSON, grafo, prompts) tem testes
próprios em test_rules_engine.py."""
from app.services import rules_engine


def _mock_matched(skills=("T1110",)):
    async def _fake(event: dict, on_progress=None) -> dict:
        return {"matched": True, "matched_skills": list(skills), "summary": "Padrão de força bruta reconhecido.", "groups": {}}
    return _fake


def _mock_no_match():
    async def _fake(event: dict, on_progress=None) -> dict:
        return {"matched": False, "matched_skills": [], "summary": "Nenhuma skill correspondente.", "groups": {}}
    return _fake


async def test_rules_engine_match_opens_incident(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())
    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
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


async def test_rules_engine_no_match_does_not_open_incident(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match())
    created = await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "healthcheck", "severity": "info"})
    await rules_engine.run_rules_engine_for_event(created.json()["id"])

    r = await client.get("/api/incidents", headers=auth_headers)
    assert r.json() == []


async def test_terminal_verdict_sets_analyzed_at(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match())
    created = await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "healthcheck", "severity": "info"})
    event_id = created.json()["id"]
    detail_before = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail_before["analyzed_at"] is None

    await rules_engine.run_rules_engine_for_event(event_id)

    detail_after = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail_after["analyzed_at"] is not None


async def test_compliance_noise_takes_fast_lane_and_skips_the_llm(client, auth_headers, ingest_headers, monkeypatch):
    """Um achado de SCA/rootcheck nunca deve chegar a chamar analyze_event
    (o LLM/LangGraph real) — a via rápida é puramente determinística."""
    called = False

    async def _fail_if_called(event: dict, on_progress=None) -> dict:
        nonlocal called
        called = True
        raise AssertionError("compliance noise não deveria chamar o motor de IA")

    monkeypatch.setattr(rules_engine, "analyze_event", _fail_if_called)
    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 5, "description": "SCA summary: Score less than 80%", "groups": ["sca"]},
    })
    event_id = created.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    assert called is False
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_status"] == "informational"
    assert detail["analyzed_at"] is not None
    assert detail["rules_engine_verdict"]["fast_lane"] is True

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert incidents == []


async def test_update_incident_status(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())
    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
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


async def test_deterministic_correlation_match_skips_the_llm_entirely(client, auth_headers, ingest_headers, monkeypatch):
    """O caso que motivou a via rápida determinística
    (app/services/correlation_rules.py): porta de autenticação exposta +
    tentativas repetidas relatadas pela própria fonte já confirmam força
    bruta (CSOC-001) por fato — não há nada para o LLM (lento, em CPU)
    "decidir" que os campos já não decidiram."""
    called = False

    async def _fail_if_called(event: dict, on_progress=None) -> dict:
        nonlocal called
        called = True
        raise AssertionError("evidência determinística já bastava — não deveria chamar a IA")

    monkeypatch.setattr(rules_engine, "analyze_event", _fail_if_called)

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 10, "description": "SSHD brute force", "frequency": 8},
        "data": {"srcip": "203.0.113.9", "dstip": "10.0.0.5", "dstport": "3389", "protocol": "TCP"},
    })
    event_id = created.json()["id"]
    base_risk_score = created.json()["risk_score"]

    await rules_engine.run_rules_engine_for_event(event_id)

    assert called is False
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_status"] == "matched"
    assert detail["matched_skills"] == ["CSOC-001"]
    assert detail["rules_engine_verdict"]["fast_lane"] is True
    assert detail["rules_engine_verdict"]["deterministic"] is True
    # Risk-Based Alerting: confirmação por fato objetivo soma ao score de
    # tráfego já calculado no ingest, em vez de deixar o incidente com a
    # mesma nota que teria se nada tivesse casado.
    assert detail["risk_score"] > base_risk_score

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert len(incidents) == 1
    assert incidents[0]["risk_score"] == detail["risk_score"]


async def test_repeated_matches_from_the_same_origin_fuse_into_one_incident(client, auth_headers, ingest_headers, monkeypatch):
    """Alert Fusion: a mesma origem confirmada várias vezes na mesma janela de
    correlação não deveria virar N incidentes — o analista investigaria a
    mesma origem repetidamente à toa."""
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched(("T1110",)))

    async def _ingest_ssh_attempt(hit_count: int) -> int:
        created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
            "rule": {"level": 10, "description": "SSHD brute force", "frequency": hit_count},
            "data": {"srcip": "198.51.100.7", "dstip": "10.0.0.5", "dstport": "22", "protocol": "TCP"},
        })
        return created.json()["id"]

    first_id = await _ingest_ssh_attempt(2)
    await rules_engine.run_rules_engine_for_event(first_id)
    second_id = await _ingest_ssh_attempt(7)
    await rules_engine.run_rules_engine_for_event(second_id)

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert len(incidents) == 1

    first_event = (await client.get(f"/api/events/{first_id}", headers=auth_headers)).json()
    second_event = (await client.get(f"/api/events/{second_id}", headers=auth_headers)).json()
    assert first_event["rules_engine_status"] == "matched"
    assert second_event["rules_engine_status"] == "matched"


async def test_cataloged_suricata_sid_skips_the_llm_entirely(client, auth_headers, ingest_headers, monkeypatch):
    """O outro caso que o motor de IA não precisa "opinar" sobre: o Suricata
    já relatou o SID (assinatura ET-Open real) e o catálogo de skills já tem
    essa assinatura (skills_data/suricata.json) — fato objetivo, igual a uma
    técnica MITRE já reportada pela fonte."""
    called = False

    async def _fail_if_called(event: dict, on_progress=None) -> dict:
        nonlocal called
        called = True
        raise AssertionError("SID já catalogado — não deveria chamar a IA")

    monkeypatch.setattr(rules_engine, "analyze_event", _fail_if_called)

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 3, "description": "Suricata: Alert - ET SCAN Amap TCP Service Scan Detected"},
        "data": {
            "src_ip": "203.0.113.44", "dest_ip": "10.0.0.5", "dest_port": "80", "proto": "TCP",
            "alert": {"signature_id": "2010371", "signature": "ET SCAN Amap TCP Service Scan Detected"},
        },
    })
    event_id = created.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    assert called is False
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_status"] == "matched"
    assert detail["matched_skills"] == ["2010371"]
    assert detail["rules_engine_verdict"]["deterministic"] is True

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert len(incidents) == 1


async def test_event_without_any_ip_skips_the_ai_entirely(client, auth_headers, ingest_headers, monkeypatch):
    """Escopo do produto: só tráfego de rede é analisado. Ciclo de vida do
    agente, FIM, sudo etc. (nenhum IP relatado) nunca deveriam chamar o motor
    de IA, mesmo sem ser especificamente SCA/rootcheck."""
    called = False

    async def _fail_if_called(event: dict, on_progress=None) -> dict:
        nonlocal called
        called = True
        raise AssertionError("evento sem IP não é tráfego de rede — não deveria chamar a IA")

    monkeypatch.setattr(rules_engine, "analyze_event", _fail_if_called)

    created = await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "Wazuh agent started", "severity": "info"})
    event_id = created.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    assert called is False
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_status"] == "informational"
    assert detail["analyzed_at"] is not None

    incidents = (await client.get("/api/incidents", headers=auth_headers)).json()
    assert incidents == []


async def test_new_incident_dispatches_notification_to_matching_connector(client, auth_headers, ingest_headers, monkeypatch):
    """O último passo do fluxo: incidente confirmado -> Slack, para um
    conector de notificação configurado para aquela criticidade."""
    sent = []

    async def _fake_dispatch(db, incident):
        sent.append((incident.code, incident.severity))

    monkeypatch.setattr(rules_engine, "dispatch_incident_notification", _fake_dispatch)
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched())

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(created.json()["id"])

    assert len(sent) == 1
    assert sent[0][0] == "INC-0001"


async def test_fused_non_escalating_event_does_not_redispatch(client, auth_headers, ingest_headers, monkeypatch):
    """Alert Fusion: a mesma origem confirmada várias vezes não deveria
    reenviar a mesma notificação/chamado a cada evento fundido."""
    dispatch_count = {"n": 0}

    async def _fake_dispatch(db, incident):
        dispatch_count["n"] += 1

    monkeypatch.setattr(rules_engine, "dispatch_incident_notification", _fake_dispatch)
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched(("T1110",)))

    async def _ingest(hit_count: int) -> int:
        created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
            "rule": {"level": 10, "description": "SSHD brute force", "frequency": hit_count},
            "data": {"srcip": "198.51.100.9", "dstip": "10.0.0.5", "dstport": "22", "protocol": "TCP"},
        })
        return created.json()["id"]

    first_id = await _ingest(2)
    await rules_engine.run_rules_engine_for_event(first_id)
    assert dispatch_count["n"] == 1  # criação dispara

    second_id = await _ingest(2)  # mesma severidade/risco — sem escalada
    await rules_engine.run_rules_engine_for_event(second_id)
    assert dispatch_count["n"] == 1  # fusão sem escalada não redispara


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
