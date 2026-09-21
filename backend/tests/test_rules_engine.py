import asyncio
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


def test_event_summary_includes_incident_context_when_present():
    # Pedido real ("agent loop"/retro-alimentação): o Supervisor precisa
    # receber o que a plataforma já sabe sobre esta origem, não só o evento
    # isolado — `rules_engine.py::_open_incident_context` monta este texto.
    summary = _event_summary({
        "type": "SSHD brute force",
        "incident_context": "Esta origem já tem um incidente aberto (INC-0042, severidade alta, aberto há 4 min, 3 evento(s) já fundido(s) nele). Técnica(s) MITRE já confirmada(s) neste incidente: T1110.",
    })
    assert "INC-0042" in summary
    assert "T1110" in summary


def test_event_summary_silent_about_incident_context_when_absent():
    summary = _event_summary({"type": "SSHD brute force"})
    assert "incidente aberto" not in summary


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


async def test_run_group_rejects_llm_confirmed_correlation_rule_without_real_evidence(monkeypatch):
    """Achado real de teste de carga (processo de aprendizado): o LLM
    confirmava CSOC-001/002/003/004 (exigem evidência real — reputação de
    IP, volume, payload — ver correlation.json `requires`) mesmo quando o
    próprio reasoning admitia que a evidência não estava presente. Se o
    caminho de IA foi alcançado, `correlation_rules.evaluate()`
    (rules_engine.py) JÁ rodou antes e não confirmou nada por fato — uma
    confirmação dessas aqui é sempre infundada e tem que ser descartada,
    nunca virar `matched_skills` real nem alimentar o aprendizado."""
    candidates = [{"source": "attack_defend", "external_id": "CSOC-003", "name": "Ataque web por reputação", "category": "x", "yaml": "y"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(candidates)}

    async def _fake_llm(*_args, **_kwargs):
        return '{"matched": true, "skills": ["CSOC-003"], "reasoning": "parece um ataque"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {"event": {"mitre": []}, "event_summary": "resumo", "on_progress": None}
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["matched"] is False
    assert verdict["skills"] == []


async def test_run_group_rejects_agent_threat_rule_without_agent_context(monkeypatch):
    """Achado real de teste de carga (processo de aprendizado): o LLM
    confirmou consistentemente "ATR-2026-00080" (Encoding-Based Prompt
    Injection Evasion — sobre instruções maliciosas ENCODADAS enviadas a um
    AGENTE/LLM) para um evento de PowerShell ofuscado num host Windows
    comum, sem nenhum agente de IA envolvido — mesma "técnica de encoding"
    na superfície, categoria de ataque totalmente diferente. Consistente o
    bastante pra passar pela checagem de consistência do learning.py e virar
    via rápida permanente para esse falso positivo."""
    candidates = [{"source": "attack_defend", "external_id": "ATR-2026-00080", "name": "Encoding-Based Prompt Injection Evasion", "category": "x", "yaml": "y"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(candidates)}

    async def _fake_llm(*_args, **_kwargs):
        return '{"matched": true, "skills": ["ATR-2026-00080"], "reasoning": "payload obfuscado"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {
        "event": {"mitre": [], "type": "Encoded PowerShell command execution with obfuscated payload", "behavior": "powershell.exe -enc ..."},
        "event_summary": "resumo", "on_progress": None,
    }
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["matched"] is False
    assert verdict["skills"] == []


async def test_run_group_accepts_agent_threat_rule_when_event_actually_mentions_an_agent(monkeypatch):
    candidates = [{"source": "attack_defend", "external_id": "ATR-2026-00080", "name": "Encoding-Based Prompt Injection Evasion", "category": "x", "yaml": "y"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(candidates)}

    async def _fake_llm(*_args, **_kwargs):
        return '{"matched": true, "skills": ["ATR-2026-00080"], "reasoning": "prompt encodado enviado ao agente de IA via MCP"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {
        "event": {"mitre": [], "type": "Suspicious tool call to MCP server", "behavior": "base64-encoded prompt sent to agent orchestrator"},
        "event_summary": "resumo", "on_progress": None,
    }
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["matched"] is True
    assert verdict["skills"] == ["ATR-2026-00080"]


async def test_run_group_unwraps_real_mcp_text_content_blocks(monkeypatch):
    """Achado real: `tools[tool_name].ainvoke(...)` (langchain_mcp_adapters)
    não devolve a lista de dicts que `search_attack_defend` retorna em
    Python — devolve o `content` bruto do protocolo MCP, que para uma tool
    anotada `-> list[dict]` vem como um content block de TEXTO por item
    (`{"type": "text", "text": "<json>", "id": ...}`). Sem desembrulhar isso,
    nenhuma candidata tinha `external_id` de verdade — a via determinística
    nunca disparava e o LLM via JSON duas vezes serializado."""
    wrapped = [{
        "type": "text", "id": "lc_1",
        "text": '{"source": "attack_defend", "external_id": "T1110", "name": "Brute Force", "category": "x", "yaml": "y"}',
    }]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(wrapped)}

    llm_called = False

    async def _fake_llm(*_args, **_kwargs):
        nonlocal llm_called
        llm_called = True
        return '{"matched": false, "skills": [], "reasoning": "não deveria nem rodar"}'

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)
    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {"event": {"mitre": ["T1110"]}, "event_summary": "resumo", "on_progress": None}
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["matched"] is True
    assert verdict["skills"] == ["T1110"]
    assert verdict["deterministic"] is True
    assert llm_called is False


async def test_run_group_treats_unparseable_mcp_error_text_as_degraded(monkeypatch):
    """Achado real: uma falha real na tool MCP (ex.: Postgres inacessível do
    subprocesso) não levanta uma exceção que o `try/except` de `_run_group`
    capturasse — vira um content block de texto de erro (não-JSON), que
    antes virava "1 candidata" com lixo dentro em vez de um veredito
    corretamente marcado como degradado."""
    wrapped = [{"type": "text", "id": "lc_1", "text": "Error executing tool search_attack_defend: connection refused"}]

    async def _fake_tools():
        return {"search_attack_defend": _FakeTool(wrapped)}

    monkeypatch.setattr(graph, "get_skill_tools", _fake_tools)

    state = {"event": {"mitre": ["T1110"]}, "event_summary": "resumo", "on_progress": None}
    verdict = await graph._run_group(state, "search_attack_defend", "prompt qualquer")

    assert verdict["matched"] is False
    assert verdict["degraded"] is True
    assert verdict["candidates_considered"] == 0


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
    assert "não julgamento de IA" in result["verdict"]["summary"]
    assert "Força Bruta" in result["verdict"]["summary"]  # nome real da técnica, não o ID cru


async def test_supervisor_skips_llm_when_no_group_found_anything_real(monkeypatch):
    # Achado real (causa raiz do delay evento->incidente): quando os 3
    # grupos avaliaram de ponta a ponta (nenhum `degraded`) e nenhum achou
    # skill real, o veredito final já está determinado — a checagem de
    # aterramento (grounding) SEMPRE forçaria "matched=False" aqui de
    # qualquer forma, então perguntar pro Supervisor (LLM, ~25s de CPU) só
    # gasta tempo sem poder mudar o resultado. Também resolve, por
    # construção, o achado real anterior: alertas de telemetria de host
    # (ex.: netstat) viravam incidente porque o Supervisor às vezes devolvia
    # "matched": true narrando a descrição do evento de volta — agora ele
    # nem chega a ser perguntado nesse caso.
    llm_called = False

    async def _fake_llm(*_args, **_kwargs):
        nonlocal llm_called
        llm_called = True
        return '{"matched": true, "matched_skills": ["mitre: nivel=7"], "summary": "parece suspeito", "recommendation": "revisar"}'

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    empty_group = {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False}
    state = {
        "event_summary": "resumo",
        "attack_defend": dict(empty_group), "network_signature": dict(empty_group), "web_application": dict(empty_group),
    }
    result = await graph.supervisor_node(state)

    assert llm_called is False
    assert result["verdict"]["matched"] is False
    assert result["verdict"]["matched_skills"] == []
    assert result["verdict"]["grounding_rejected"] is False  # nada foi rejeitado — o LLM nem chegou a ser perguntado


async def test_supervisor_still_rejects_llm_hallucination_when_a_group_is_degraded(monkeypatch):
    """A otimização acima só se aplica quando os 3 grupos avaliaram de ponta
    a ponta — se algum estiver `degraded`, o Supervisor ainda é consultado
    (o caso é genuinamente inconclusivo, não "sem skill confirmada"), e a
    checagem de aterramento continua obrigatória pra esse caminho."""
    async def _hallucinating_llm(*_args, **_kwargs):
        return '{"matched": true, "matched_skills": ["mitre: nivel=7"], "summary": "parece suspeito", "recommendation": "revisar"}'

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _hallucinating_llm)

    empty_group = {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False}
    degraded_group = {"matched": False, "skills": [], "reasoning": "RAG indisponível", "candidates_considered": 0, "degraded": True, "deterministic": False}
    state = {
        "event_summary": "resumo",
        "attack_defend": dict(degraded_group), "network_signature": dict(empty_group), "web_application": dict(empty_group),
    }
    result = await graph.supervisor_node(state)

    assert result["verdict"]["matched"] is False
    assert result["verdict"]["matched_skills"] == []
    assert result["verdict"]["grounding_rejected"] is True


async def test_supervisor_can_confirm_when_a_group_found_a_real_skill(monkeypatch):
    async def _confirming_llm(*_args, **_kwargs):
        return '{"matched": true, "matched_skills": ["texto livre do LLM, ignorado"], "summary": "confirmado", "recommendation": "bloquear"}'

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _confirming_llm)

    state = {
        "event_summary": "resumo",
        "attack_defend": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
    }
    result = await graph.supervisor_node(state)

    assert result["verdict"]["matched"] is True
    assert result["verdict"]["matched_skills"] == ["T1110"]  # da skill real do grupo, não do texto livre do LLM
    assert result["verdict"]["grounding_rejected"] is False


async def test_supervisor_deduplicates_same_technique_matched_by_two_groups(monkeypatch):
    """Achado real (ticket GLPI): "Assinatura(s)/skill(s) confirmada(s):
    T1110, T1110" — a mesma técnica MITRE agora pode exact-matchar tanto em
    attack_defend quanto em network_signature (catálogo unificado por
    técnica, skills_catalog.py), e a concatenação simples dos dois grupos
    duplicava o ID."""
    async def _confirming_llm(*_args, **_kwargs):
        return '{"matched": true, "matched_skills": [], "summary": "confirmado", "recommendation": "bloquear"}'

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _confirming_llm)

    state = {
        "event_summary": "resumo",
        "attack_defend": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": True},
        "network_signature": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": True},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
    }
    result = await graph.supervisor_node(state)

    assert result["verdict"]["matched_skills"] == ["T1110"]


async def test_deterministic_match_gets_a_real_recommendation_not_a_placeholder(monkeypatch):
    """Achado real (ticket GLPI): "recomendações genéricas, não falam o
    propósito" — o caminho determinístico (fato objetivo, sem chamada de
    LLM) devolvia literalmente "Revisar manualmente — skill(s) casada(s)
    mas o Supervisor (IA) não consolidou o resumo.", em vez de citar a
    técnica/regra real já confirmada. Este é o caminho mais comum agora
    (catálogo unificado por técnica MITRE, skills_catalog.py torna o exact
    match muito mais frequente), então esse placeholder era o que a maioria
    dos tickets via."""
    llm_called = False

    async def _fake_llm(*_args, **_kwargs):
        nonlocal llm_called
        llm_called = True
        return "{}"

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _fake_llm)

    state = {
        "event_summary": "resumo",
        "attack_defend": {"matched": True, "skills": ["T1110"], "reasoning": "exato", "candidates_considered": 1, "degraded": False, "deterministic": True},
        "network_signature": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
    }
    result = await graph.supervisor_node(state)

    assert llm_called is False  # continua sem gastar CPU do Ollama para um fato já confirmado
    verdict = result["verdict"]
    assert "não consolidou o resumo" not in verdict["recommendation"]
    assert "Força Bruta" in verdict["recommendation"]  # nome real da técnica, não o ID cru
    assert "Força Bruta" in verdict["summary"]


async def test_supervisor_deduplicates_when_llm_confirms_two_groups_with_same_technique(monkeypatch):
    """Mesmo achado real acima, mas pelo caminho não-determinístico (LLM
    confirma o consenso dos grupos) — `real_skills` (grounding) tem o mesmo
    risco de duplicata que `_deterministic_consolidation`."""
    async def _confirming_llm(*_args, **_kwargs):
        return '{"matched": true, "matched_skills": [], "summary": "confirmado", "recommendation": "bloquear"}'

    monkeypatch.setattr(graph, "_invoke_llm_with_retry", _confirming_llm)

    state = {
        "event_summary": "resumo",
        "attack_defend": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "network_signature": {"matched": True, "skills": ["T1110"], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
        "web_application": {"matched": False, "skills": [], "reasoning": "", "candidates_considered": 1, "degraded": False, "deterministic": False},
    }
    result = await graph.supervisor_node(state)

    assert result["verdict"]["matched_skills"] == ["T1110"]


def test_all_group_prompts_and_supervisor_prompt_exist_and_are_non_trivial():
    for p in (prompts.ATTACK_DEFEND_GROUP_PROMPT, prompts.NETWORK_SIGNATURE_GROUP_PROMPT,
              prompts.WEB_APPLICATION_GROUP_PROMPT, prompts.SUPERVISOR_PROMPT):
        assert len(p) > 200
        assert "JSON" in p


async def test_persist_progress_updates_event_before_final_verdict(client, auth_headers, ingest_headers):
    """Cobre a visibilidade em tempo real (app/services/rules_engine.py
    _persist_progress): a UI precisa ver o agente "trabalhando" grupo a grupo,
    não só o veredito final depois de até ~900s."""
    from app.services import rules_engine

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
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


async def test_run_rules_engine_gates_db_access_behind_the_wide_semaphore_too(client, ingest_headers):
    """Achado real de teste de carga: uma rajada de ingestão agendava um
    `run_rules_engine_for_event` por evento imediatamente — mesmo os que iam
    cair no fast lane faziam 2-4 idas ao Postgres cada ANTES de chegar no
    antigo único semáforo (que só protegia a chamada de LLM). Com centenas de
    tasks concorrentes fazendo isso ao mesmo tempo, o event loop único do
    processo ficava ocupado o bastante para uma rota de leitura sem relação
    nenhuma (ex.: GET /api/dashboard/eps) demorar dezenas de segundos.
    `_INGEST_PROCESSING_CONCURRENCY` entra ANTES de qualquer acesso a banco —
    prova aqui: com o semáforo tomado por fora, o evento nem chega a ser
    buscado no banco (`rules_engine_status` continua "pending", não muda para
    "analyzing" nem "informational")."""
    from app.services import rules_engine

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 5, "description": "Integrity checksum changed"},
        "data": {},
    })
    event_id = created.json()["id"]

    sem = rules_engine._INGEST_PROCESSING_CONCURRENCY
    for _ in range(12):  # satura TODAS as vagas do semáforo (capacidade 12), não só uma
        await sem.acquire()
    try:
        task = asyncio.ensure_future(rules_engine.run_rules_engine_for_event(event_id))
        await asyncio.sleep(0.05)
        assert not task.done()
        async with rules_engine.SessionLocal() as db:
            event = await db.get(rules_engine.Event, event_id)
            assert event.rules_engine_status == "pending"
    finally:
        for _ in range(12):
            sem.release()

    await asyncio.wait_for(task, timeout=5.0)
    async with rules_engine.SessionLocal() as db:
        event = await db.get(rules_engine.Event, event_id)
        assert event.rules_engine_status == "informational"  # host-only, sem IP -> fast lane


async def test_run_rules_engine_never_leaves_an_event_stuck_after_a_crash(client, ingest_headers, monkeypatch):
    """Achado real de teste de carga: quando o Postgres derruba uma conexão
    sozinho (`idle_in_transaction_session_timeout`), a próxima operação da
    task que a usava levanta uma exceção de verdade — a vaga do semáforo
    libera certinho, mas sem este tratamento o EVENTO ficava "analyzing"
    para sempre (nem erro visível, nem reprocessado no próximo restart, já
    que só "pending"/"analyzing" são requeued e ele já parecia estar em
    processamento). Simula a falha diretamente (`_run_rules_engine_for_event`
    explode) pra provar que o evento sempre termina com um status final."""
    from app.services import rules_engine

    created = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 10, "description": "SSHD brute force"},
        "data": {"srcip": "203.0.113.9", "dstip": "10.0.0.5", "dstport": "22", "protocol": "TCP"},
    })
    event_id = created.json()["id"]

    async def _boom(_event_id):
        raise ConnectionResetError("conexão derrubada pelo Postgres (simulado)")

    monkeypatch.setattr(rules_engine, "_run_rules_engine_for_event", _boom)

    await rules_engine.run_rules_engine_for_event(event_id)

    async with rules_engine.SessionLocal() as db:
        event = await db.get(rules_engine.Event, event_id)
        assert event.rules_engine_status == "no_match"
        assert event.rules_engine_verdict["technical_failure"] is True
        assert "conexão derrubada" in event.rules_engine_verdict["summary"]
        assert event.analyzed_at is not None


async def test_campaign_context_flags_same_technique_confirmed_by_a_different_origin(client, ingest_headers, monkeypatch):
    """Segundo hop de correlação (análise de mercado seção 8.3): a MESMA
    técnica MITRE já CONFIRMADA num incidente aberto de outra origem entra
    como contexto pro Supervisor avaliar o evento novo — sinal de campanha,
    não origem isolada."""
    from app.services import rules_engine

    async def _mock_matched(event, on_progress=None):
        return {
            "matched": True, "matched_skills": ["T1110"], "summary": "Confirmado.",
            "recommendation": "Bloquear.", "groups": {"attack_defend": {"skills": ["T1110"]}},
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_matched)
    first = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "9.9.9.9", "dstip": "10.0.0.22", "dstport": "22", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(first.json()["id"])

    captured: dict = {}

    async def _capture(event, on_progress=None):
        captured.update(event)
        return {
            "matched": True, "matched_skills": ["T1110"], "summary": "Confirmado.",
            "recommendation": "Bloquear.", "groups": {"attack_defend": {"skills": ["T1110"]}},
        }

    monkeypatch.setattr(rules_engine, "analyze_event", _capture)
    second = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "SSHD brute force", "mitre": {"id": ["T1110"]}},
        "data": {"srcip": "1.2.3.4", "dstip": "10.0.0.99", "dstport": "22", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(second.json()["id"])

    assert "Padrão de campanha" in captured["incident_context"]
    assert "T1110" in captured["incident_context"]


async def test_campaign_context_flags_multiple_origins_targeting_the_same_destination(client, ingest_headers, monkeypatch):
    """Segundo hop de correlação: o MESMO destino sendo mirado por várias
    origens ao mesmo tempo entra como contexto pro Supervisor, mesmo sem
    nenhuma técnica MITRE confirmada ainda em outro incidente."""
    from app.services import rules_engine

    async def _mock_unmatched(event, on_progress=None):
        return {"matched": False, "matched_skills": [], "summary": "sem skill", "recommendation": None, "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _mock_unmatched)
    first = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "Port scan"},
        "data": {"srcip": "1.1.1.1", "dstip": "10.0.0.50", "dstport": "22", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(first.json()["id"])

    captured: dict = {}

    async def _capture(event, on_progress=None):
        captured.update(event)
        return {"matched": False, "matched_skills": [], "summary": "sem skill", "recommendation": None, "groups": {}}

    monkeypatch.setattr(rules_engine, "analyze_event", _capture)
    second = await client.post("/api/ingest/wazuh", headers=ingest_headers, json={
        "rule": {"level": 12, "description": "Port scan"},
        "data": {"srcip": "2.2.2.2", "dstip": "10.0.0.50", "dstport": "22", "protocol": "TCP"},
    })
    await rules_engine.run_rules_engine_for_event(second.json()["id"])

    assert "outra(s) origem(ns) distinta(s)" in captured["incident_context"]
    assert "10.0.0.50" in captured["incident_context"]


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
