import os

import pytest

from app.agents import prompts
from app.agents.graph import _event_summary, _parse_json


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


def test_all_group_prompts_and_supervisor_prompt_exist_and_are_non_trivial():
    for p in (prompts.ATTACK_DEFEND_GROUP_PROMPT, prompts.NETWORK_SIGNATURE_GROUP_PROMPT,
              prompts.WEB_APPLICATION_GROUP_PROMPT, prompts.SUPERVISOR_PROMPT):
        assert len(p) > 200
        assert "JSON" in p


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
