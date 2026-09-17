from app.services.event_triage import fast_lane_verdict, is_compliance_noise


def test_sca_only_groups_are_compliance_noise():
    assert is_compliance_noise({"rule": {"groups": ["sca"]}}) is True


def test_rootcheck_only_groups_are_compliance_noise():
    assert is_compliance_noise({"rule": {"groups": ["rootcheck"]}}) is True


def test_mixed_groups_with_a_security_group_are_not_noise():
    """Um achado de rootcheck que também casa outro grupo de regra (ex.:
    alguma correlação de segurança) não deve ser filtrado — só o caso 100%
    compliance/inventário toma a via rápida."""
    assert is_compliance_noise({"rule": {"groups": ["rootcheck", "malware"]}}) is False


def test_sudo_events_are_not_noise():
    assert is_compliance_noise({"rule": {"groups": ["syslog", "sudo"]}}) is False


def test_no_groups_is_not_noise():
    assert is_compliance_noise({"rule": {}}) is False
    assert is_compliance_noise({}) is False


def test_fast_lane_verdict_is_explicit_about_skipping_ai():
    verdict = fast_lane_verdict("SCA summary: Score less than 80%")
    assert verdict["matched"] is False
    assert verdict["fast_lane"] is True
    assert "via rápida" in verdict["recommendation"] or "SCA" in verdict["recommendation"]
