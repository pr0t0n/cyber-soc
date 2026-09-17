import os

import pytest

from app.agents import prompts
from app.agents.graph import _event_summary, _exact_id_matches, _parse_json


def test_parse_json_extracts_object_from_noisy_llm_output():
    noisy = 'Claro, aqui está minha análise:\n{"matched": true, "skills": ["T1110"], "reasoning": "ok"}\nFim.'
    parsed = _parse_json(noisy)
    assert parsed == {"matched": True, "skills": ["T1110"], "reasoning": "ok"}


def test_parse_json_returns_none_for_non_json():
    assert _parse_json("não sei responder isso.") is None


def test_event_summary_includes_key_fields():
    event = {
        "type": "SSHD brute force", "severity": "critica", "src_ip": "185.220.101.8",
        "src_port": None, "dst_ip": "10.0.0.22", "dst_port": "3389", "protocol": "TCP",
        "mitre": ["T1110"], "behavior": "Failed password for root",
    }
    summary = _event_summary(event)
    assert "185.220.101.8" in summary
    assert "T1110" in summary
    assert "critica" in summary


def test_event_summary_includes_hit_count_and_threat_intel_when_present():
    """Gap corrigido: antes o resumo do evento (o que a IA e o RAG efetivamente
    veem) não incluía contagem de tentativas nem o veredito de threat intel do
    IP de origem — a IA nunca sabia que o IP já era confirmado malicioso."""
    event = {
        "type": "SSHD brute force", "severity": "critica", "src_ip": "1.2.3.4",
        "mitre": ["T1110"], "hit_count": 12, "rule_ref": "Wazuh regra 5720, nível 12: SSHD brute force",
        "enrichment": {"assessment": {"reasons": ["AbuseIPDB: reputação maliciosa (100/100, 275 relatos)."]}},
    }
    summary = _event_summary(event)
    assert "tentativas/repetições relatadas pela fonte=12" in summary
    assert "Wazuh regra 5720" in summary
    assert "AbuseIPDB" in summary


def test_event_summary_is_explicit_when_hit_count_is_missing():
    summary = _event_summary({"type": "SSHD brute force", "mitre": ["T1110"]})
    assert "tentativas/repetições relatadas pela fonte=não informado" in summary


def test_exact_id_matches_finds_candidate_sharing_mitre_id_reported_by_source():
    """O booster determinístico: se a fonte já tagueou o evento com T1110 e o
    catálogo tem uma skill com external_id=T1110, isso é confirmado
    independente do julgamento (frágil, modelo pequeno) do LLM."""
    event = {"mitre": ["T1110"]}
    candidates = [
        {"external_id": "T1110", "name": "Brute Force"},
        {"external_id": "T1595", "name": "Active Scanning"},
    ]
    forced = _exact_id_matches(event, candidates)
    assert [c["external_id"] for c in forced] == ["T1110"]


def test_exact_id_matches_empty_when_source_reported_no_mitre_technique():
    assert _exact_id_matches({"mitre": []}, [{"external_id": "T1110", "name": "Brute Force"}]) == []


def test_all_group_prompts_and_supervisor_prompt_exist_and_are_non_trivial():
    for p in (prompts.ATTACK_DEFEND_GROUP_PROMPT, prompts.NETWORK_SIGNATURE_GROUP_PROMPT,
              prompts.WEB_APPLICATION_GROUP_PROMPT, prompts.SUPERVISOR_PROMPT):
        assert len(p) > 200
        assert "JSON" in p


async def test_persist_progress_updates_event_before_final_verdict(client, auth_headers):
    """Cobre a visibilidade em tempo real (app/services/rules_engine.py
    _persist_progress): a UI precisa ver o agente "trabalhando" grupo a grupo,
    não só o veredito final depois de até ~900s."""
    from app.services import rules_engine

    created = await client.post("/api/ingest/wazuh", json={
        "rule": {"level": 12, "description": "SSHD brute force"},
        "data": {"srcip": "185.220.101.8", "dstip": "10.0.0.22", "dstport": "3389", "protocol": "TCP"},
    })
    event_id = created.json()["id"]

    await rules_engine._persist_progress(
        event_id, "attack_defend",
        {"matched": False, "skills": [], "reasoning": "sem correspondência", "candidates_considered": 3},
    )

    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_status"] == "analyzing"
    assert detail["rules_engine_verdict"]["stages_done"] == 1
    assert detail["rules_engine_verdict"]["groups"]["attack_defend"]["candidates_considered"] == 3

    listing = (await client.get("/api/events", headers=auth_headers)).json()
    row = next(i for i in listing["items"] if i["id"] == event_id)
    assert row["stages_done"] == 1 and row["stages_total"] == 3

    await rules_engine._persist_progress(
        event_id, "network_signature",
        {"matched": False, "skills": [], "reasoning": "sem correspondência", "candidates_considered": 5},
    )
    detail = (await client.get(f"/api/events/{event_id}", headers=auth_headers)).json()
    assert detail["rules_engine_verdict"]["stages_done"] == 2
    assert set(detail["rules_engine_verdict"]["groups"]) == {"attack_defend", "network_signature"}


@pytest.mark.skipif(not os.getenv("LIVE_RULES_ENGINE"), reason="LIVE_RULES_ENGINE não definido (precisa de Ollama real rodando)")
async def test_live_analyze_event_end_to_end():
    from app.agents.graph import analyze_event

    verdict = await analyze_event({
        "type": "SSHD brute force", "severity": "critica", "src_ip": "185.220.101.8",
        "dst_ip": "10.0.0.22", "dst_port": "3389", "protocol": "TCP",
        "mitre": ["T1110"], "behavior": "Failed password for root repeated 40 times",
    })
    assert "matched" in verdict
    assert "matched_skills" in verdict
