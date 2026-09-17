import os

import pytest

from app.agents import graph, prompts
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


def test_event_summary_flags_correlated_activity_from_same_origin():
    """Um analista de SOC nunca julga um evento isolado — várias ocorrências
    da mesma origem em minutos é sinal por si só."""
    summary = _event_summary({"type": "Port scan", "correlated_count": 12})
    assert "12 evento(s)" in summary
    assert "não é um evento isolado" in summary


def test_event_summary_silent_about_correlation_when_isolated():
    summary = _event_summary({"type": "Port scan", "correlated_count": 1})
    assert "evento(s) nos últimos" not in summary


class _FakeTool:
    def __init__(self, candidates):
        self._candidates = candidates

    async def ainvoke(self, args):
        return self._candidates


async def test_run_group_skips_llm_when_exact_id_already_matches(monkeypatch):
    """O caso mais comum e mais importante de acertar rápido: a fonte já
    reportou a técnica, o catálogo já tem a skill — não há nada para o LLM
    (lento, em CPU) "decidir" que os fatos já não decidiram."""
    candidates = [{"source": "attack", "external_id": "T1110", "name": "Brute Force", "category": "x", "yaml": "y"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(candidates)}

    llm_called = False

    async def _fake_llm(*_args, **_kwargs):
        nonlocal llm_called
        llm_called = True
        return '{"matched": false, "skills": [], "reasoning": "não deveria nem rodar"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {"event": {"mitre": ["T1110"]}, "event_summary": "resumo", "on_progress": None}
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict == {
        "matched": True, "skills": ["T1110"],
        "reasoning": "Correspondência exata de técnica já reportada pela fonte com o catálogo: ['Brute Force'].",
        "candidates_considered": 1, "degraded": False, "deterministic": True,
    }
    assert llm_called is False


async def test_run_group_calls_llm_when_no_exact_id_match(monkeypatch):
    candidates = [{"source": "attack", "external_id": "T1595", "name": "Active Scanning", "category": "x", "yaml": "y"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(candidates)}

    async def _fake_llm(*_args, **_kwargs):
        return '{"matched": true, "skills": ["T1595"], "reasoning": "avaliado pela IA"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {"event": {"mitre": ["T1110"]}, "event_summary": "resumo", "on_progress": None}
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["deterministic"] is False
    assert verdict["matched"] is True
    assert verdict["reasoning"] == "avaliado pela IA"


async def test_supervisor_skips_llm_when_any_group_is_deterministic(monkeypatch):
    llm_called = False

    async def _fake_llm(*_args, **_kwargs):
        nonlocal llm_called
        llm_called = True
        return "{}"

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {
        "event_summary": "resumo",
        "attack_defend": {
            "matched": True, "skills": ["T1110"], "reasoning": "exato", "candidates_considered": 1,
            "degraded": False, "deterministic": True,
        },
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": True, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 0, "degraded": True, "deterministic": False},
    }
    result = await graph.supervisor_node(state)

    assert llm_called is False
    assert result["verdict"]["matched"] is True
    assert result["verdict"]["matched_skills"] == ["T1110"]
    assert "sem chamada de IA" in result["verdict"]["summary"]


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
