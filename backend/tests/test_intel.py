import os

import pytest

from app.services import threat_intel as ti


def test_is_public_ip():
    assert ti.is_public_ip("185.220.101.1")
    assert not ti.is_public_ip("10.0.0.5")
    assert not ti.is_public_ip("127.0.0.1")
    assert not ti.is_public_ip(None)


def test_score_traffic_risky_port():
    result = ti.score_traffic(dst_port="3389", protocol="TCP", abuse=None)
    assert result["risk_score"] >= 35
    assert "RDP" in " ".join(result["reasons"])


def test_score_traffic_clean():
    result = ti.score_traffic(dst_port="443", protocol="TCP", abuse=None)
    assert result["risk_score"] == 0
    assert result["level"] == "baixo"


def test_score_traffic_abuse_confidence_dominates():
    abuse = {"status": "ok", "abuse_confidence_score": 95, "total_reports": 40, "is_tor": False}
    result = ti.score_traffic(dst_port="443", protocol="TCP", abuse=abuse)
    assert result["risk_score"] == 95
    assert result["is_malicious"] is True


def test_score_traffic_protocol_mismatch():
    result = ti.score_traffic(dst_port="53", protocol="TCP", abuse=None)
    assert result["risk_score"] >= 15


def test_score_traffic_shodan_c2_ports():
    shodan = {"status": "ok", "found": True, "ports": [80, 4444], "tags": [], "vulns": []}
    result = ti.score_traffic(dst_port="443", protocol="TCP", abuse=None, shodan=shodan)
    assert result["risk_score"] >= 60
    assert "Shodan" in " ".join(result["reasons"])


def test_score_traffic_shodan_not_found_is_neutral():
    shodan = {"status": "ok", "found": False}
    result = ti.score_traffic(dst_port="443", protocol="TCP", abuse=None, shodan=shodan)
    assert result["risk_score"] == 0


@pytest.mark.skipif(not os.getenv("ABUSEIPDB_API_KEY"), reason="ABUSEIPDB_API_KEY não definido")
async def test_live_abuseipdb_tor_node():
    res = await ti.query_abuseipdb(os.environ["ABUSEIPDB_API_KEY"], "185.220.101.1")
    assert res["status"] == "ok"


@pytest.mark.skipif(not os.getenv("SHODAN_API_KEY"), reason="SHODAN_API_KEY não definido")
async def test_live_shodan_host():
    res = await ti.query_shodan(os.environ["SHODAN_API_KEY"], "1.1.1.1")
    assert res["status"] == "ok"
    assert res["found"] is True
