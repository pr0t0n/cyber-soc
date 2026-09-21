from app.services.event_triage import (
    deterministic_verdict,
    fast_lane_verdict,
    is_compliance_noise,
    is_network_traffic,
    non_network_fast_lane_verdict,
)


def test_deterministic_verdict_aggregates_mitre_from_matches_without_duplicates():
    matches = [
        {"id": "9000001", "mitre": ["T1595"], "title": "Port scan", "recommendation": "..."},
        {"id": "CSOC-002", "mitre": ["T1595", "T1046"], "title": "Correlação", "recommendation": "..."},
    ]
    verdict = deterministic_verdict(matches)
    assert verdict["mitre"] == ["T1595", "T1046"]


def test_deterministic_verdict_mitre_empty_when_no_match_carries_technique():
    matches = [{"id": "999", "mitre": [], "title": "Sem técnica mapeada", "recommendation": "..."}]
    assert deterministic_verdict(matches)["mitre"] == []


def test_deterministic_verdict_deduplicates_matches_with_the_same_id():
    """Mesma classe de achado real do dedup em graph.py: `matched_skills`
    duplicado (ex.: "T1110, T1110") num ticket confunde o analista — o mesmo
    id nunca deveria aparecer duas vezes no veredito determinístico."""
    matches = [
        {"id": "9000001", "mitre": ["T1595"], "title": "Port scan", "recommendation": "Bloquear."},
        {"id": "9000001", "mitre": ["T1595"], "title": "Port scan", "recommendation": "Bloquear."},
    ]
    verdict = deterministic_verdict(matches)
    assert verdict["matched_skills"] == ["9000001"]
    assert verdict["recommendation"] == "9000001: Bloquear."


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


def test_rootcheck_with_generic_ossec_wrapper_is_still_noise():
    """Bug real corrigido: o Wazuh SEMPRE inclui o grupo genérico "ossec"
    junto de "rootcheck" em alertas reais (`groups=["ossec","rootcheck"]`) —
    sem descartar esse wrapper antes de comparar, nenhum achado real de
    rootcheck era pego pela via rápida (só o "sca" puro, sem wrapper, era)."""
    assert is_compliance_noise({"rule": {"groups": ["ossec", "rootcheck"]}}) is True


def test_syscheck_with_generic_ossec_wrapper_is_not_noise():
    """Mudança de arquivo (syscheck) é relevante de verdade para segurança —
    não deve virar via rápida só porque carrega o wrapper genérico "ossec"."""
    assert is_compliance_noise({"rule": {"groups": ["ossec", "syscheck", "syscheck_file"]}}) is False


def test_generic_wrapper_alone_is_not_noise():
    """"ossec" sozinho (ex.: comando netstat monitorado) não tem sinal
    discriminante nenhum — não deve virar via rápida por exclusão."""
    assert is_compliance_noise({"rule": {"groups": ["ossec"]}}) is False


def test_fast_lane_verdict_is_explicit_about_skipping_ai():
    verdict = fast_lane_verdict("SCA summary: Score less than 80%")
    assert verdict["matched"] is False
    assert verdict["fast_lane"] is True
    assert "via rápida" in verdict["recommendation"] or "SCA" in verdict["recommendation"]


def test_event_with_src_ip_is_network_traffic():
    assert is_network_traffic(src_ip="185.220.101.8", dst_ip=None) is True


def test_event_with_only_dst_ip_is_network_traffic():
    assert is_network_traffic(src_ip=None, dst_ip="10.0.0.5") is True


def test_event_without_any_ip_is_not_network_traffic():
    """Escopo do produto: FIM, rootcheck, SCA, inventário e ciclo de vida do
    agente nunca carregam IP — não descrevem tráfego, só estado do host."""
    assert is_network_traffic(src_ip=None, dst_ip=None) is False


def test_loopback_only_dst_ip_is_not_network_traffic():
    # Achado real: `_translate_wazuh` usa `agent.ip` como fallback de dst_ip
    # para telemetria pura de host (netstat) — isso virava "127.0.0.1", que
    # não é destino de tráfego nenhum, só o agente relatando a si mesmo.
    assert is_network_traffic(src_ip=None, dst_ip="127.0.0.1") is False
    assert is_network_traffic(src_ip=None, dst_ip="::1") is False


def test_loopback_dst_ip_with_real_src_ip_is_still_network_traffic():
    # Uma origem de verdade se conectando a localhost (ex.: proxy/tunnel
    # local) ainda é tráfego real — só o CASO PURO "só loopback, sem
    # origem nenhuma" é excluído.
    assert is_network_traffic(src_ip="185.220.101.8", dst_ip="127.0.0.1") is True


def test_non_network_fast_lane_verdict_is_explicit_about_scope():
    verdict = non_network_fast_lane_verdict("Wazuh agent started")
    assert verdict["matched"] is False
    assert verdict["fast_lane"] is True
    assert "tráfego de rede" in verdict["recommendation"]
