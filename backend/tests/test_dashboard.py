from app.services import rules_engine


async def _ingest_sample(client, ingest_headers):
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "id": "1", "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    return r.json()["id"]


async def _mock_matched(event: dict, on_progress=None) -> dict:
    return {"matched": True, "matched_skills": ["T1110"], "summary": "Força bruta reconhecida.", "groups": {}}


async def test_summary(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    r = await client.get("/api/dashboard/summary", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["severity_counts"]["critica"] == 1
    assert body["mitre_coverage_pct"] > 0


async def test_eps_and_funnel(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    r = await client.get("/api/dashboard/eps", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] == 1
    assert body["funnel"][0]["stage"] == "eps"
    assert body["funnel"][0]["pct_of_total"] == 100.0


async def test_eps_has_no_analysis_delay_when_nothing_was_analyzed_yet(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    body = (await client.get("/api/dashboard/eps", headers=auth_headers)).json()
    assert body["analysis_delay_seconds"] is None


async def test_eps_reports_real_analysis_delay_from_received_to_analyzed(client, auth_headers, ingest_headers, monkeypatch):
    """`analysis_delay_seconds` (ao lado da caixa de EPS) precisa refletir o
    tempo real recebido->analisado dos últimos 5 minutos — não um placeholder
    nem uma média histórica dominada por picos antigos de LLM lento."""
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/eps", headers=auth_headers)).json()
    assert body["analysis_delay_seconds"] is not None
    assert 0 <= body["analysis_delay_seconds"] < 300


async def test_summary_filters_by_tag(client, auth_headers, ingest_headers):
    created = await client.post("/api/admin/connectors", headers=auth_headers, json={
        "name": "Wazuh VALID", "kind": "siem", "type": "wazuh", "config": {"client_tag": "VALID"},
    })
    token = created.json()["ingest_token"]
    await client.post("/api/ingest/wazuh", json={"rule": {"level": 12}}, headers={"Authorization": f"Bearer {token}"})
    # Fonte diferente (conector "de fábrica" do conftest, não o Wazuh VALID acima).
    await client.post("/api/ingest/generic", headers=ingest_headers, json={"type": "outro", "severity": "critica"})

    tagged = (await client.get("/api/dashboard/summary?tag=VALID", headers=auth_headers)).json()
    assert tagged["severity_counts"]["critica"] == 1
    all_events = (await client.get("/api/dashboard/summary", headers=auth_headers)).json()
    assert all_events["severity_counts"]["critica"] == 2


async def test_mitre_heatmap(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    r = await client.get("/api/dashboard/mitre-heatmap", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    tactic = next(t for t in body["tactics"] if t["name"] == "Acesso Inicial")
    cell = next(c for c in tactic["techniques"] if c["id"] == "T1110")
    assert cell["count"] == 1


async def test_connectors_status_reflects_configured_connectors(client, auth_headers):
    """O setup de teste (conftest.py) cadastra 3 conectores siem 'de fábrica'
    (wazuh/elastic/generic) — a ingestão só funciona com integração
    cadastrada, então "zero conectores" deixou de ser o estado padrão."""
    r = await client.get("/api/dashboard/connectors-status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 3


async def test_tickets_status_honest_when_no_glpi_ticket_exists(client, auth_headers):
    r = await client.get("/api/dashboard/tickets-status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["summary"]["total"] == 0


async def test_tickets_status_reflects_real_glpi_ticket_counts(client, auth_headers):
    from app.db import SessionLocal
    from app.models import Incident

    async with SessionLocal() as db:
        db.add(Incident(code="INC-5001", title="Teste", status="backlog", severity="alta", glpi_ticket_id=101))
        db.add(Incident(code="INC-5002", title="Teste", status="concluido", severity="critica", glpi_ticket_id=102))
        db.add(Incident(code="INC-5003", title="Sem ticket", status="backlog", severity="media"))
        await db.commit()

    body = (await client.get("/api/dashboard/tickets-status", headers=auth_headers)).json()
    assert body["summary"]["total"] == 2  # só os com glpi_ticket_id
    assert body["summary"]["abertos"] == 1
    assert body["summary"]["fechados"] == 1
    codes = {r["incident_code"] for r in body["recent"]}
    assert codes == {"INC-5001", "INC-5002"}


async def test_incidents_status_reflects_real_incidents(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)  # motor de regras "casou" -> abre incidente em backlog

    r = await client.get("/api/dashboard/incidents-status", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["backlog"] == 1
    assert body["summary"]["total"] == 1
    assert body["recent"][0]["status"] == "backlog"


async def test_risk_heatmap_shape(client, auth_headers, ingest_headers):
    # _ingest_sample usa uma data fixa fora da janela de 7 dias do heatmap;
    # aqui usamos "agora" para cair dentro da janela.
    await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
    })
    r = await client.get("/api/dashboard/risk-heatmap", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["grid"]) == 7 and len(body["grid"][0]) == 24
    assert any(v > 0 for row in body["grid"] for v in row)


async def test_world_map_empty_without_geo(client, auth_headers, ingest_headers):
    # AUTO_GEO_ON_INGEST=false nos testes -> nenhum evento tem lat/lon.
    await _ingest_sample(client, ingest_headers)
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


async def test_analysis_metrics_before_any_analysis(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    r = await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["analyzed_by_ai_count"] == 0
    assert body["stability_pct"] is None  # sem amostra ainda, não "100%" nem "0%"
    assert body["backlog"]["count"] == 1
    assert body["backlog"]["oldest_seconds"] is not None


async def test_analysis_metrics_after_matched_event_computes_speed_and_sla(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    r = await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)
    body = r.json()
    assert body["analyzed_by_ai_count"] == 1
    assert body["stability_pct"] == 100.0  # groups vazio -> nenhum degradado
    assert body["analysis_speed"]["sample_size"] == 1
    assert body["analysis_speed"]["median_seconds"] is not None
    assert body["sla_event_to_incident"]["sample_size"] == 1
    assert body["backlog"]["count"] == 0


async def test_analysis_metrics_counts_degraded_group_against_efficiency(client, auth_headers, ingest_headers, monkeypatch):
    async def _mock_degraded(event: dict, on_progress=None) -> dict:
        return {
            "matched": False, "matched_skills": [], "summary": "inconclusivo",
            "groups": {"attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": True}},
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_degraded)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["degraded_count"] == 1
    assert body["stability_pct"] == 0.0


async def test_analysis_metrics_counts_grounding_rejections_separately_from_degraded(client, auth_headers, ingest_headers, monkeypatch):
    # `stability_pct` (era "eficiência") não é um sinal de qualidade da
    # decisão — uma alucinação corrigida pela validação de aterramento
    # (graph.py::supervisor_node) nunca é "degradação" (a chamada de LLM
    # completou normalmente, só respondeu sem base real). Sem uma métrica
    # separada, isso ficava 100% "estável" o tempo todo mesmo quando a
    # validação estava corrigindo o Supervisor.
    async def _mock_grounding_rejected(event: dict, on_progress=None) -> dict:
        return {
            "matched": False, "matched_skills": [], "summary": "sem skill real",
            "groups": {
                "attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
                "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
                "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
            },
            "grounding_rejected": True,
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_grounding_rejected)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["grounding_rejected_count"] == 1
    assert body["degraded_count"] == 0
    assert body["stability_pct"] == 100.0  # nenhuma degradação de infra — a métrica antiga não capturava a alucinação


async def test_analysis_metrics_counts_deterministic_matches_separately_from_llm(client, auth_headers, ingest_headers, monkeypatch):
    """Sinal direto do catálogo unificado por técnica MITRE
    (skills_catalog.py) + do desembrulho de content blocks do MCP
    (graph.py `_unwrap_mcp_candidates`): antes dessas correções, os grupos
    network_signature/web_application nunca resolviam por correspondência
    exata (suas candidatas eram SID/rule-id/UUID crus, nunca uma técnica
    ATT&CK) — `deterministic_count` é a prova de que a via rápida real está
    disparando, não só o julgamento do LLM."""
    async def _mock_deterministic(event: dict, on_progress=None) -> dict:
        return {
            "matched": True, "matched_skills": ["T1595"], "summary": "scan confirmado",
            "groups": {
                "attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 5, "degraded": False, "deterministic": False},
                "network_signature": {"matched": True, "skills": ["T1595"], "reasoning": "exato", "candidates_considered": 5, "degraded": False, "deterministic": True},
                "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 5, "degraded": False, "deterministic": False},
            },
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_deterministic)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["deterministic_count"] == 1
    assert body["deterministic_pct"] == 100.0


async def test_analysis_metrics_hydration_full_when_mitre_present(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)  # já tem rule.mitre.id
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["matched_count"] == 1
    assert body["hydrated_count"] == 1
    assert body["hydration_pct"] == 100.0


async def test_analysis_metrics_hydration_low_when_mitre_and_enrichment_missing(client, auth_headers, ingest_headers, monkeypatch):
    # 100% de eficiência (nenhuma análise degradada) não deve virar 100% de
    # hidratação quando o evento casado não carrega nem técnica MITRE nem
    # enriquecimento — a métrica que o dashboard mostrava antes confundia as
    # duas coisas (ver comentário em app/api/dashboard.py).
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "id": "2", "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 12, "description": "Suricata: Alert - generic"},
        "data": {"srcip": "185.220.101.9", "dstip": "10.0.0.23", "dstport": "22", "protocol": "TCP"},
    })
    event_id = r.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["stability_pct"] == 100.0
    assert body["matched_count"] == 1
    assert body["hydrated_count"] == 0
    assert body["hydration_pct"] == 0.0


async def test_ai_path_writes_back_mitre_from_attack_defend_group_only(client, auth_headers, ingest_headers, monkeypatch):
    # `matched_skills` mistura os 3 grupos (attack_defend usa técnica MITRE
    # como id da skill; network_signature/web_application usam SID Suricata/
    # id de regra ModSecurity — formatos incompatíveis com `event.mitre`).
    # Só o `skills` de dentro de `groups.attack_defend` pode ir para lá.
    async def _mock_matched_via_attack_defend(event: dict, on_progress=None) -> dict:
        return {
            "matched": True, "matched_skills": ["T1110", "2010371"], "summary": "Força bruta reconhecida.",
            "groups": {
                "attack_defend": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
                "network_signature": {"matched": True, "skills": ["2010371"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
            },
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched_via_attack_defend)
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "id": "10", "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.10", "dstip": "10.0.0.24", "dstport": "22", "protocol": "TCP"},
    })
    event_id = r.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    event = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert event["mitre"] == ["T1110"]  # não "2010371" (SID, não é técnica MITRE)


async def test_fast_lane_signature_match_writes_back_mitre_technique(client, auth_headers, ingest_headers, monkeypatch):
    # SID 2010371 (ET SCAN Amap TCP Service Scan Detected) é classtype
    # "attempted-recon" no catálogo real — antes desta correção, uma
    # assinatura confirmada pela via rápida nunca escrevia técnica MITRE de
    # volta no evento (só o que a própria fonte já relatasse na ingestão,
    # quase nunca preenchido para Suricata/ModSecurity). A via rápida deve
    # decidir sozinha, sem nunca chamar o motor de IA.
    async def _fail_if_called(event: dict, on_progress=None) -> dict:
        raise AssertionError("via rápida determinística deveria ter decidido sem chamar a IA")

    monkeypatch.setattr(rules_engine, "analyze_event", _fail_if_called)
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "id": "9", "timestamp": "2026-06-25T14:23:00Z",
        "rule": {"level": 5, "description": "Suricata: Alert - ET SCAN Amap TCP Service Scan Detected"},
        "data": {"alert": {"signature_id": "2010371"}, "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5"},
    })
    event_id = r.json()["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    event = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert event["mitre"] == ["T1595"]


async def test_analysis_metrics_fast_lane_excluded_from_ai_efficiency(client, auth_headers, ingest_headers):
    await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 5, "description": "SCA summary: Score less than 80%", "groups": ["sca"]},
    })
    event_id = (await client.get("/api/events", headers=auth_headers)).json()["items"][0]["id"]
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert body["fast_lane_count"] == 1
    assert body["analyzed_by_ai_count"] == 0  # via rápida não conta como "analisado por IA"
    assert body["backlog"]["count"] == 0


_NOT_MATCHED_VERDICT = {
    "matched": False, "matched_skills": [], "summary": "Nenhuma skill do catálogo casou.",
    "recommendation": "Nenhuma ação necessária — sem skill correspondente.",
    "groups": {
        "attack_defend": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
    },
}


async def test_new_origin_burst_with_no_skill_match_is_flagged_suspicious(client, auth_headers, ingest_headers, monkeypatch):
    # Pedido real: não descartar como "no_match" um evento sem skill
    # confirmada quando a ORIGEM em si já é um sinal (nunca apareceu antes e
    # gerou uma rajada agora) — flag para investigação humana posterior, não
    # um "nada a ver aqui" silencioso.
    async def _not_matched(event, on_progress=None):
        return _NOT_MATCHED_VERDICT

    monkeypatch.setattr(rules_engine, "analyze_event", _not_matched)
    # 3, não 5: correlated_count >= 5 já vira "varredura confirmada" pelo
    # CSOC-002 (via rápida determinística) antes de chegar na IA — este
    # teste tem que ficar ABAIXO desse limiar pra provar o sinal mais
    # sensível da linha de base semanal, não o da via rápida.
    src_ip = "203.0.113.201"
    event_id = None
    for i in range(3):
        r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
            "id": str(900 + i), "timestamp": "2026-06-25T14:23:00Z",
            "rule": {"level": 5, "description": "Evento de teste sem skill conhecida"},
            "data": {"srcip": src_ip, "dstip": "10.0.0.30", "dstport": "443", "protocol": "TCP"},
        })
        event_id = r.json()["id"]

    await rules_engine.run_rules_engine_for_event(event_id)

    event = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert event["rules_engine_status"] == "suspicious"
    assert "nova" in event["recommendation"].lower()

    metrics = (await client.get("/api/dashboard/analysis-metrics", headers=auth_headers)).json()
    assert metrics["suspicious_count"] == 1

    watchlist = (await client.get("/api/dashboard/watchlist", headers=auth_headers)).json()
    assert len(watchlist["items"]) == 1
    assert watchlist["items"][0]["id"] == event_id
    assert watchlist["items"][0]["src_ip"] == src_ip


async def test_no_match_without_burst_stays_no_match_not_suspicious(client, auth_headers, ingest_headers, monkeypatch):
    async def _not_matched(event, on_progress=None):
        return _NOT_MATCHED_VERDICT

    monkeypatch.setattr(rules_engine, "analyze_event", _not_matched)
    event_id = await _ingest_sample(client, ingest_headers)  # 1 evento isolado, sem rajada
    await rules_engine.run_rules_engine_for_event(event_id)

    event = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert event["rules_engine_status"] == "no_match"


async def test_eps_funnel_ends_in_incidents(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)

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


async def test_learned_patterns_endpoint_lists_only_promoted_patterns(client, auth_headers):
    from app.db import SessionLocal
    from app.models import LearnedPattern

    async with SessionLocal() as db:
        db.add(LearnedPattern(pattern_key="SSHD brute force", confirmations=3, promoted=True, mitre=["T1110"]))
        db.add(LearnedPattern(pattern_key="Ainda não promovido", confirmations=1, promoted=False))
        await db.commit()

    body = (await client.get("/api/dashboard/learned-patterns", headers=auth_headers)).json()
    keys = [i["pattern_key"] for i in body["items"]]
    assert keys == ["SSHD brute force"]
    assert body["items"][0]["mitre"] == ["T1110"]


async def test_incident_narratives_and_timeline_and_traffic_baseline_endpoints_respond(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    narratives = (await client.get("/api/dashboard/incident-narratives", headers=auth_headers)).json()
    assert len(narratives["items"]) == 1
    assert narratives["items"][0]["code"].startswith("INC-")

    timeline = (await client.get("/api/dashboard/activity-timeline", headers=auth_headers)).json()
    assert any(i["kind"] == "incident_created" for i in timeline["items"])

    baseline = (await client.get("/api/dashboard/traffic-baseline", headers=auth_headers)).json()
    assert isinstance(baseline["items"], list)


async def test_mtt_metrics_empty_when_no_incidents(client, auth_headers):
    body = (await client.get("/api/dashboard/mtt-metrics", headers=auth_headers)).json()
    assert body["mttd"]["sample_size"] == 0
    assert body["mttr_respond"]["sample_size"] == 0
    assert body["mttc_contain"]["sample_size"] == 0
    assert body["mttr_repair"]["sample_size"] == 0


async def test_mtt_metrics_mttd_counts_every_incident_but_later_phases_need_their_own_marks(
    client, auth_headers, ingest_headers, monkeypatch,
):
    """Achado real: um incidente recém-criado (ainda "Novo"/"Atribuído" no
    GLPI) não tem como contribuir pro MTTR/MTTC/MTTR (reparo) — os marcos que
    delimitam essas fases (`glpi_takeintoaccount_at` em diante) só existem
    depois que `sync_all_glpi_statuses` os observa. Isso não é um bug: o
    ciclo de vida dele ainda não chegou lá. MTTD por si só já está disponível
    (não depende de nenhum marco do GLPI, só de `Incident.created_at`)."""
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    body = (await client.get("/api/dashboard/mtt-metrics", headers=auth_headers)).json()
    assert body["mttd"]["sample_size"] == 1
    assert body["mttr_respond"]["sample_size"] == 0
    assert body["mttc_contain"]["sample_size"] == 0
    assert body["mttr_repair"]["sample_size"] == 0


async def test_mtt_metrics_computes_each_phase_from_its_own_real_glpi_marks(client, auth_headers, ingest_headers, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Incident

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        incident = (await db.execute(select(Incident))).scalars().one()
        incident.created_at = now
        incident.glpi_takeintoaccount_at = now + timedelta(minutes=5)   # MTTR = 5min
        incident.glpi_planned_at = now + timedelta(minutes=15)          # MTTC = 10min
        incident.glpi_solved_at = now + timedelta(minutes=45)           # MTTR (reparo) = 30min
        await db.commit()

    body = (await client.get("/api/dashboard/mtt-metrics", headers=auth_headers)).json()
    assert body["mttr_respond"]["sample_size"] == 1
    assert body["mttr_respond"]["avg_seconds"] == 300.0
    assert body["mttc_contain"]["sample_size"] == 1
    assert body["mttc_contain"]["avg_seconds"] == 600.0
    assert body["mttr_repair"]["sample_size"] == 1
    assert body["mttr_repair"]["avg_seconds"] == 1800.0


async def test_mtt_metrics_repair_falls_back_to_respond_mark_when_containment_never_observed(
    client, auth_headers, ingest_headers, monkeypatch,
):
    """Nem todo ticket passa por "Processing (Planned)" antes de ser
    resolvido (pode ir direto de Atribuído pra Resolvido) — sem isso, o MTTR
    (reparo) desses incidentes nunca entraria em nenhuma amostra."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Incident

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(event_id)

    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        incident = (await db.execute(select(Incident))).scalars().one()
        incident.created_at = now
        incident.glpi_takeintoaccount_at = now + timedelta(minutes=5)
        incident.glpi_solved_at = now + timedelta(minutes=20)  # sem glpi_planned_at
        await db.commit()

    body = (await client.get("/api/dashboard/mtt-metrics", headers=auth_headers)).json()
    assert body["mttc_contain"]["sample_size"] == 0
    assert body["mttr_repair"]["sample_size"] == 1
    assert body["mttr_repair"]["avg_seconds"] == 900.0  # 15min: takeintoaccount -> solved


async def test_attack_vector_empty_without_events(client, auth_headers):
    body = (await client.get("/api/dashboard/attack-vector", headers=auth_headers)).json()
    assert body == {"sources": [], "categories": [], "cells": []}


async def test_attack_vector_groups_by_source_and_mitre_tactic_with_result_breakdown(
    client, auth_headers, ingest_headers, monkeypatch,
):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    matched_event_id = await _ingest_sample(client, ingest_headers)  # wazuh, mitre=T1110 (Acesso a Credenciais)
    await rules_engine.run_rules_engine_for_event(matched_event_id)

    no_mitre_event_id = (await client.post("/api/ingest/generic", headers=ingest_headers, json={
        "type": "Ping de rotina", "severity": "info",
        "src_ip": "10.0.0.50", "dst_ip": "10.0.0.1", "protocol": "ICMP",
    })).json()["id"]

    async def _mock_no_match(event: dict, on_progress=None) -> dict:
        return {"matched": False, "matched_skills": [], "summary": "sem correspondência", "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match)
    await rules_engine.run_rules_engine_for_event(no_mitre_event_id)

    body = (await client.get("/api/dashboard/attack-vector", headers=auth_headers)).json()
    assert "wazuh" in body["sources"] and "generic" in body["sources"]
    assert "Sem técnica MITRE" in body["categories"]

    by_key = {(c["source"], c["category"]): c for c in body["cells"]}
    mitre_cell = next(c for (s, cat), c in by_key.items() if s == "wazuh" and cat != "Sem técnica MITRE")
    assert mitre_cell["matched"] == 1 and mitre_cell["total"] == 1
    generic_cell = by_key[("generic", "Sem técnica MITRE")]
    assert generic_cell["no_match"] == 1 and generic_cell["total"] == 1


async def test_kpis_empty_platform(client, auth_headers):
    body = (await client.get("/api/dashboard/kpis", headers=auth_headers)).json()
    assert body["sla"] == {"target_hours": body["sla"]["target_hours"], "compliant": 0, "total": 0, "compliance_pct": None}
    assert body["workload_reduction_pct"] is None
    assert body["data_sources"] == []


async def test_kpis_workload_reduction_reflects_events_that_never_became_incidents(
    client, auth_headers, ingest_headers, monkeypatch,
):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    matched_id = await _ingest_sample(client, ingest_headers)
    await rules_engine.run_rules_engine_for_event(matched_id)

    async def _mock_no_match(event: dict, on_progress=None) -> dict:
        return {"matched": False, "matched_skills": [], "summary": "sem correspondência", "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match)
    for _ in range(3):
        no_match_id = (await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
            "rule": {"level": 5, "description": "Ping de rotina"},
            "data": {"srcip": "10.0.0.9", "dstip": "10.0.0.1", "protocol": "ICMP"},
        })).json()["id"]
        await rules_engine.run_rules_engine_for_event(no_match_id)

    body = (await client.get("/api/dashboard/kpis", headers=auth_headers)).json()
    # 1 incidente de 4 eventos -> 3 nunca viraram trabalho real (75%)
    assert body["workload_reduction_pct"] == 75.0


async def test_kpis_sla_compliance_uses_severity_specific_target(client, auth_headers, ingest_headers, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Incident

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = await _ingest_sample(client, ingest_headers)  # severidade "critica" (level 12)
    await rules_engine.run_rules_engine_for_event(event_id)

    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        incident = (await db.execute(select(Incident))).scalars().one()
        assert incident.severity == "critica"  # alvo de 4h
        incident.created_at = now
        incident.glpi_solved_at = now + timedelta(hours=10)  # estourou o prazo de crítica
        await db.commit()

    body = (await client.get("/api/dashboard/kpis", headers=auth_headers)).json()
    assert body["sla"]["total"] == 1
    assert body["sla"]["compliant"] == 0
    assert body["sla"]["compliance_pct"] == 0.0


async def test_kpis_data_sources_relevance_breakdown(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    matched_id = await _ingest_sample(client, ingest_headers)  # wazuh
    await rules_engine.run_rules_engine_for_event(matched_id)

    generic_id = (await client.post("/api/ingest/generic", headers=ingest_headers, json={
        "type": "Ping de rotina", "severity": "info", "src_ip": "10.0.0.50", "dst_ip": "10.0.0.1",
    })).json()["id"]

    async def _mock_no_match(event: dict, on_progress=None) -> dict:
        return {"matched": False, "matched_skills": [], "summary": "sem correspondência", "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_no_match)
    await rules_engine.run_rules_engine_for_event(generic_id)

    body = (await client.get("/api/dashboard/kpis", headers=auth_headers)).json()
    by_source = {d["source"]: d for d in body["data_sources"]}
    assert by_source["wazuh"] == {"source": "wazuh", "total": 1, "relevant": 1, "relevant_pct": 100.0}
    assert by_source["generic"] == {"source": "generic", "total": 1, "relevant": 0, "relevant_pct": 0.0}


async def test_confusion_matrix_empty_without_any_review(client, auth_headers, ingest_headers):
    await _ingest_sample(client, ingest_headers)
    body = (await client.get("/api/dashboard/confusion-matrix", headers=auth_headers)).json()
    assert body["reviewed_count"] == 0
    assert body["total_events"] == 1
    assert body["accuracy_pct"] is None
    assert body["precision_pct"] is None


async def test_asset_risk_endpoint_ranks_hosts_by_computed_risk(client, auth_headers, ingest_headers, monkeypatch):
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    matched_id = await _ingest_sample(client, ingest_headers)  # SSHD brute force, sem agent_hostname no payload
    await rules_engine.run_rules_engine_for_event(matched_id)

    body = (await client.get("/api/dashboard/asset-risk", headers=auth_headers)).json()
    assert body["window_days"] == 30
    assert len(body["items"]) >= 1
    assert body["items"][0]["risk_score"] >= 0


async def test_environment_seasonality_groups_by_tag_with_volume_grid_and_attack_types(
    client, auth_headers, ingest_headers, monkeypatch,
):
    # _ingest_sample usa uma data fixa fora da janela de 7 dias da
    # sazonalidade; aqui usamos "agora" (sem "timestamp" -> default) pra
    # cair dentro da janela, mesmo padrão de test_risk_heatmap_shape.
    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    matched_id = created.json()["id"]
    await rules_engine.run_rules_engine_for_event(matched_id)

    body = (await client.get("/api/dashboard/environment-seasonality", headers=auth_headers)).json()
    assert len(body["days"]) == 7
    assert len(body["environments"]) >= 1
    env = body["environments"][0]
    assert env["total_events"] >= 1
    assert len(env["grid"]) == 7 and all(len(row) == 24 for row in env["grid"])
    assert sum(sum(row) for row in env["grid"]) == env["total_events"]
    assert len(env["top_attack_types"]) >= 1
    assert env["top_attack_types"][0]["count"] >= 1


async def test_environment_seasonality_buckets_untagged_events_instead_of_dropping_them(client, auth_headers):
    from datetime import datetime, timezone

    from app.db import SessionLocal
    from app.models import Event

    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        db.add(Event(timestamp=now, received_at=now, source="generic", type="Sem tag", severity="info", tag=None))
        await db.commit()

    body = (await client.get("/api/dashboard/environment-seasonality", headers=auth_headers)).json()
    tags = {e["tag"] for e in body["environments"]}
    assert "Sem tag" in tags


async def test_confusion_matrix_computes_precision_and_recall_from_analyst_review(client, auth_headers, ingest_headers):
    tp_id = await _ingest_sample(client, ingest_headers)
    fp_id = await _ingest_sample(client, ingest_headers)
    tn_id = await _ingest_sample(client, ingest_headers)
    fn_id = await _ingest_sample(client, ingest_headers)

    await client.patch(f"/api/events/{tp_id}/verdict", headers=auth_headers, json={"verdict": "true_positive"})
    await client.patch(f"/api/events/{fp_id}/verdict", headers=auth_headers, json={"verdict": "false_positive"})
    await client.patch(f"/api/events/{tn_id}/verdict", headers=auth_headers, json={"verdict": "true_negative"})
    await client.patch(f"/api/events/{fn_id}/verdict", headers=auth_headers, json={"verdict": "false_negative"})

    body = (await client.get("/api/dashboard/confusion-matrix", headers=auth_headers)).json()
    assert body["true_positive"] == 1 and body["false_positive"] == 1
    assert body["true_negative"] == 1 and body["false_negative"] == 1
    assert body["reviewed_count"] == 4
    assert body["total_events"] == 4
    assert body["accuracy_pct"] == 50.0  # (TP+TN)/reviewed = 2/4
    assert body["precision_pct"] == 50.0  # TP/(TP+FP) = 1/2
    assert body["recall_pct"] == 50.0  # TP/(TP+FN) = 1/2
    assert body["f1_pct"] == 50.0
    assert body["false_positive_rate_pct"] == 50.0  # FP/(FP+TN) = 1/2
    assert body["false_negative_rate_pct"] == 50.0  # FN/(FN+TP) = 1/2
