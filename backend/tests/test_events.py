"""API de eventos (app/api/events.py) — reclassificação humana do veredito
(`PATCH /{id}/verdict`) existe só pra medir a matriz de confusão real
(dashboard.py /confusion-matrix), nunca pra sobrescrever o veredito do motor."""


async def _ingest_sample(client, ingest_headers) -> int:
    r = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    return r.json()["id"]


async def test_new_event_has_no_analyst_verdict_yet(client, auth_headers, ingest_headers):
    event_id = await _ingest_sample(client, ingest_headers)
    body = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert body["analyst_verdict"] is None


async def test_analyst_can_set_and_clear_verdict(client, auth_headers, ingest_headers):
    event_id = await _ingest_sample(client, ingest_headers)

    r = await client.patch(f"/api/events/{event_id}/verdict", headers=auth_headers, json={"verdict": "true_positive"})
    assert r.status_code == 200
    assert r.json()["analyst_verdict"] == "true_positive"

    body = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert body["analyst_verdict"] == "true_positive"

    listed = (await client.get("/api/events", headers=auth_headers)).json()
    assert listed["items"][0]["analyst_verdict"] == "true_positive"

    r = await client.patch(f"/api/events/{event_id}/verdict", headers=auth_headers, json={"verdict": None})
    assert r.status_code == 200
    assert r.json()["analyst_verdict"] is None


async def test_verdict_rejects_unknown_value(client, auth_headers, ingest_headers):
    event_id = await _ingest_sample(client, ingest_headers)
    r = await client.patch(f"/api/events/{event_id}/verdict", headers=auth_headers, json={"verdict": "maybe"})
    assert r.status_code == 400


async def test_verdict_404_for_unknown_event(client, auth_headers):
    r = await client.patch("/api/events/999999/verdict", headers=auth_headers, json={"verdict": "true_positive"})
    assert r.status_code == 404


async def test_verdict_never_changes_the_engines_own_status(client, auth_headers, ingest_headers):
    """Achado real evitado por design: reclassificar como "false_positive" não
    pode silenciosamente virar `rules_engine_status="no_match"` — o motor e o
    analista discordarem é exatamente o que a matriz de confusão mede."""
    event_id = await _ingest_sample(client, ingest_headers)
    before = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()

    await client.patch(f"/api/events/{event_id}/verdict", headers=auth_headers, json={"verdict": "false_positive"})

    after = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert after["rules_engine_status"] == before["rules_engine_status"]
    assert after["analyst_verdict"] == "false_positive"


async def test_verdict_false_positive_demotes_a_promoted_learned_pattern(client, auth_headers, ingest_headers, monkeypatch):
    """PATCH /{id}/verdict fecha o loop de aprendizado humano de ponta a
    ponta: um `false_positive` pra uma skill já promovida em learning.py
    reverte a promoção na hora (learning.apply_analyst_feedback), em vez de
    esperar uma auditoria manual descobrir depois que a via rápida estava
    errada."""
    from app.db import SessionLocal
    from app.services import learning, rules_engine

    async def _mock_matched(event, on_progress=None):
        return {"matched": True, "matched_skills": ["T1110"], "summary": "Força bruta reconhecida.", "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    event_id = None
    for _ in range(learning.PROMOTION_THRESHOLD):
        event_id = await _ingest_sample(client, ingest_headers)
        await rules_engine.run_rules_engine_for_event(event_id)

    async with SessionLocal() as db:
        assert await learning.lookup(db, "SSHD brute force") is not None

    r = await client.patch(f"/api/events/{event_id}/verdict", headers=auth_headers, json={"verdict": "false_positive"})
    assert r.status_code == 200
    assert r.json()["learned_pattern_demoted"] is True

    async with SessionLocal() as db:
        assert await learning.lookup(db, "SSHD brute force") is None
