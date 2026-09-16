import yaml

from app.services import skills_catalog


ALL_SOURCES = {"attack", "d3fend", "suricata", "modsecurity", "sigma", "agent_threats"}


def test_load_all_returns_real_data_from_all_six_sources():
    items = skills_catalog.load_all()
    sources = {i["source"] for i in items}
    assert sources == ALL_SOURCES
    assert len(items) > 1500  # catálogo real baixado, não uma amostra artificial


def test_attack_technique_yaml_is_well_formed_and_real():
    items = [i for i in skills_catalog.load_all() if i["source"] == "attack" and i["external_id"] == "T1110"]
    assert items, "T1110 (Brute Force) deveria estar no catálogo real do ATT&CK"
    skill = items[0]
    parsed = yaml.safe_load(skill["yaml_content"])
    assert parsed["id"] == "T1110"
    assert parsed["name"] == "Brute Force"
    assert "Credential Access" in parsed["tactics"] or "Credencial" in " ".join(parsed["tactics"])


def test_d3fend_technique_has_real_id_and_tactic():
    items = [i for i in skills_catalog.load_all() if i["source"] == "d3fend" and i["external_id"] == "D3-AL"]
    assert items, "D3-AL (Account Locking) deveria estar no catálogo real do D3FEND"
    assert items[0]["category"] == "Evict"


def test_suricata_and_modsecurity_have_real_identifiers():
    items = skills_catalog.load_all()
    suricata = [i for i in items if i["source"] == "suricata"]
    modsec = [i for i in items if i["source"] == "modsecurity"]
    assert all(i["external_id"].isdigit() for i in suricata)  # sid real
    assert all(i["external_id"].isdigit() for i in modsec)  # id real da regra CRS


def test_sigma_rules_have_real_uuids_and_mitre_tags():
    items = [i for i in skills_catalog.load_all() if i["source"] == "sigma"]
    assert len(items) > 300
    with_mitre = [i for i in items if "mitre=" in i["search_text"] and not i["search_text"].endswith("mitre=")]
    assert with_mitre, "pelo menos algumas regras Sigma reais devem ter técnicas MITRE mapeadas"


def test_agent_threat_rules_have_real_atr_ids_and_owasp_refs():
    items = [i for i in skills_catalog.load_all() if i["source"] == "agent_threats"]
    assert len(items) > 50
    assert all(i["external_id"].startswith("ATR-") for i in items)
    parsed = yaml.safe_load(items[0]["yaml_content"])
    assert parsed["owasp_agentic"] or parsed["owasp_llm"]


async def test_skills_api_lists_and_filters_by_source(client, auth_headers):
    r = await client.get("/api/skills?source=d3fend&limit=5", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] > 0
    assert all(item["source"] == "d3fend" for item in body["items"])


async def test_skills_api_returns_yaml_for_one_skill(client, auth_headers):
    listed = await client.get("/api/skills?source=attack&limit=1", headers=auth_headers)
    skill_id = listed.json()["items"][0]["id"]
    r = await client.get(f"/api/skills/{skill_id}", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "skill:" in body["yaml"]
    yaml.safe_load(body["yaml"])  # não levanta -> YAML válido


async def test_skills_sources_summary(client, auth_headers):
    r = await client.get("/api/skills/sources", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert {s["source"] for s in body["sources"]} == ALL_SOURCES
    assert body["total"] > 1500
