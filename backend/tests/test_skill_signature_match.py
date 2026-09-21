"""SID do Suricata / id de regra do ModSecurity que a própria fonte já
relatou, batendo contra o catálogo real de skills (skills_data/suricata.json,
skills_data/modsecurity.json) — mesmo princípio de _exact_id_matches (MITRE
ATT&CK), aplicado às outras fontes de skill: fato objetivo, sem LLM."""
from app.services import skill_signature_match


def test_matches_a_real_cataloged_suricata_sid():
    raw = {"data": {"alert": {"signature_id": "2010371"}}}
    matches = skill_signature_match.evaluate(raw)
    assert len(matches) == 1
    assert matches[0]["id"] == "2010371"
    assert "Amap" in matches[0]["title"]


def test_suricata_classtype_maps_to_mitre_technique():
    # SID 2010371 é classtype "attempted-recon" no catálogo real — sem esse
    # mapeamento, uma assinatura confirmada ficava com mitre=[] (achado real:
    # cobertura MITRE travada em ~0% mesmo com milhares de matches
    # determinísticos confirmados).
    raw = {"data": {"alert": {"signature_id": "2010371"}}}
    matches = skill_signature_match.evaluate(raw)
    assert matches[0]["mitre"] == ["T1595"]


def test_unknown_suricata_sid_does_not_match():
    raw = {"data": {"alert": {"signature_id": "999999999"}}}
    assert skill_signature_match.evaluate(raw) == []


def test_no_alert_field_does_not_match():
    assert skill_signature_match.evaluate({"data": {}}) == []
    assert skill_signature_match.evaluate({}) == []


def test_matches_a_real_cataloged_modsecurity_rule_id():
    raw = {"data": {"id": "941100"}}
    matches = skill_signature_match.evaluate(raw)
    assert len(matches) == 1
    assert matches[0]["id"] == "941100"
    assert "XSS" in matches[0]["title"]
    assert matches[0]["mitre"] == ["T1190"]  # categoria "xss" -> Exploit Public-Facing Application


def test_matches_modsecurity_rule_id_nested_under_modsecurity_key():
    raw = {"data": {"modsecurity": {"id": "941100"}}}
    matches = skill_signature_match.evaluate(raw)
    assert len(matches) == 1
    assert matches[0]["id"] == "941100"


def test_unknown_modsecurity_rule_id_does_not_match():
    assert skill_signature_match.evaluate({"data": {"id": "0"}}) == []


def test_both_suricata_and_modsecurity_can_match_the_same_event():
    """Não deveria acontecer na prática (um evento não é as duas fontes ao
    mesmo tempo), mas a função não deve assumir exclusividade."""
    raw = {"data": {"alert": {"signature_id": "2010371"}, "id": "941100"}}
    matches = skill_signature_match.evaluate(raw)
    assert {m["id"] for m in matches} == {"2010371", "941100"}
