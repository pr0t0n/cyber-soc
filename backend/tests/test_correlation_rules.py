"""As regras de correlação (CSOC-00x, skills_data/correlation.json) descrevem
condições checáveis (porta, contagem de tentativas, reputação de IP) — antes
disso, elas só existiam como texto para o LLM "opinar" sobre, o que fazia até
o caso mais óbvio esperar minutos na fila do Ollama. Aqui testamos que a
confirmação acontece por fato, sem IA."""
from app.services import correlation_rules


def _enrichment(risk_score: int = 0) -> dict:
    return {"assessment": {"risk_score": risk_score}}


def test_csoc_001_matches_auth_port_with_reported_hit_count():
    event = {"dst_port": "3389", "hit_count": 6, "enrichment": _enrichment()}
    assert [m["id"] for m in correlation_rules.evaluate(event)] == ["CSOC-001"]


def test_csoc_001_matches_auth_port_with_correlated_volume():
    event = {"dst_port": "22", "correlated_count": 5, "enrichment": _enrichment()}
    assert "CSOC-001" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_001_matches_auth_port_with_confirmed_ip_reputation():
    event = {"dst_port": "445", "enrichment": _enrichment(risk_score=90)}
    assert "CSOC-001" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_001_ignores_high_volume_on_a_non_auth_port():
    """Volume alto por si só, numa porta que não é de autenticação, não é
    força bruta — o portão de porta é obrigatório (`requires.target_port_in`)."""
    event = {"dst_port": "8080", "hit_count": 50, "enrichment": _enrichment()}
    assert "CSOC-001" not in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_001_port_alone_without_evidence_does_not_match():
    event = {"dst_port": "22", "enrichment": _enrichment()}
    assert correlation_rules.evaluate(event) == []


def test_csoc_002_matches_high_correlation_regardless_of_port():
    event = {"dst_port": None, "correlated_count": 9, "enrichment": _enrichment()}
    assert "CSOC-002" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_002_matches_confirmed_reputation_alone():
    event = {"correlated_count": 1, "enrichment": _enrichment(risk_score=80)}
    assert "CSOC-002" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_003_requires_web_traffic_gate():
    """Um IP malicioso batendo numa porta não-web (ex.: SSH) não deve virar
    'ataque de aplicação web' só pela reputação isolada."""
    event = {"dst_port": "22", "protocol": "TCP", "enrichment": _enrichment(risk_score=95)}
    assert "CSOC-003" not in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_003_matches_web_port_with_confirmed_reputation():
    event = {"dst_port": "443", "enrichment": _enrichment(risk_score=85)}
    assert "CSOC-003" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_003_matches_web_port_with_attack_payload():
    event = {
        "dst_port": "80",
        "behavior": "GET /index.php?id=1 UNION SELECT username,password FROM users",
        "enrichment": _enrichment(),
    }
    assert "CSOC-003" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_004_matches_c2_port_with_confirmed_reputation():
    event = {"dst_port": "4444", "enrichment": _enrichment(risk_score=70)}
    assert "CSOC-004" in [m["id"] for m in correlation_rules.evaluate(event)]


def test_csoc_004_ignores_c2_port_without_confirmed_reputation():
    event = {"dst_port": "4444", "enrichment": _enrichment(risk_score=30)}
    assert "CSOC-004" not in [m["id"] for m in correlation_rules.evaluate(event)]


def test_fast_lane_verdict_is_none_when_nothing_confirms():
    assert correlation_rules.fast_lane_verdict({"dst_port": "9999", "enrichment": _enrichment()}) is None


def test_fast_lane_verdict_is_explicit_about_being_deterministic_and_fast():
    event = {"dst_port": "3389", "hit_count": 10, "enrichment": _enrichment()}
    verdict = correlation_rules.fast_lane_verdict(event)
    assert verdict["matched"] is True
    assert verdict["matched_skills"] == ["CSOC-001"]
    assert verdict["deterministic"] is True
    assert verdict["fast_lane"] is True
    assert "CSOC-001" in verdict["recommendation"]


def test_fast_lane_verdict_lists_every_rule_that_matched():
    """Uma varredura de portas de autenticação com volume alto pode
    legitimamente confirmar força bruta E reconhecimento ao mesmo tempo —
    nada obriga escolher só uma."""
    event = {"dst_port": "22", "hit_count": 20, "correlated_count": 15, "enrichment": _enrichment()}
    verdict = correlation_rules.fast_lane_verdict(event)
    assert set(verdict["matched_skills"]) == {"CSOC-001", "CSOC-002"}
