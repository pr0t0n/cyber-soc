import yaml

from app.services import skills_catalog


ALL_SOURCES = {"attack_defend", "network_signature", "web_application"}


def test_load_all_returns_real_data_unified_by_technique():
    items = skills_catalog.load_all()
    sources = {i["source"] for i in items}
    assert sources == ALL_SOURCES
    # Suricata/ModSecurity/Sigma deixaram de ser listas fragmentadas por
    # SID/rule-id/UUID próprios (~1750 linhas somadas) — agora são fundidas
    # por técnica ATT&CK, então o catálogo total encolhe bastante mesmo
    # cobrindo o mesmo conteúdo real; nunca deveria voltar a crescer sem
    # controle nem cair a ponto de sugerir que uma fonte sumiu.
    assert 500 < len(items) < 1000
    keys = [(i["source"], i["external_id"]) for i in items]
    assert len(keys) == len(set(keys)), "chave (source, external_id) deve ser única"


def test_attack_technique_yaml_is_well_formed_and_real():
    items = [i for i in skills_catalog.load_all() if i["source"] == "attack_defend" and i["external_id"] == "T1110"]
    assert items, "T1110 (Brute Force) deveria estar no catálogo real do ATT&CK"
    skill = items[0]
    parsed = yaml.safe_load(skill["yaml_content"])
    assert parsed["id"] == "T1110"
    assert parsed["name"] == "Brute Force"
    assert "Credential Access" in parsed["tactics"] or "Credencial" in " ".join(parsed["tactics"])


def test_d3fend_technique_has_real_id_and_tactic():
    items = [i for i in skills_catalog.load_all() if i["source"] == "attack_defend" and i["external_id"] == "D3-AL"]
    assert items, "D3-AL (Account Locking) deveria estar no catálogo real do D3FEND"
    assert items[0]["category"] == "Evict"


def test_network_signature_skill_fuses_real_suricata_and_sigma_evidence_for_a_technique():
    """T1595 (Active Scanning) tem assinaturas reais de scan mapeadas
    (classtype attempted-recon/successful-recon-limited) — a skill unificada
    de rede para esta técnica precisa citar essa evidência real, não só
    repetir o nome da técnica."""
    items = [i for i in skills_catalog.load_all() if i["source"] == "network_signature" and i["external_id"] == "T1595"]
    assert items, "T1595 deveria ter uma skill de rede unificada (Suricata attempted-recon está mapeado para ela)"
    parsed = yaml.safe_load(items[0]["yaml_content"])
    assert parsed["technique_id"] == "T1595"
    assert parsed["suricata_signatures"]["total"] > 0
    assert parsed["suricata_signatures"]["sample"]


def test_web_application_skill_fuses_real_modsecurity_evidence_for_a_technique():
    items = [i for i in skills_catalog.load_all() if i["source"] == "web_application" and i["external_id"] == "T1190"]
    assert items, "T1190 (Exploit Public-Facing Application) deveria ter skill web (ModSecurity sqli/rce/xss mapeiam para ela)"
    parsed = yaml.safe_load(items[0]["yaml_content"])
    assert parsed["modsecurity_rules"]["total"] > 0


def test_technique_without_mappable_signature_still_has_attack_defend_skill_only():
    """Nem toda técnica ATT&CK tem assinatura de rede/WAF mapeável — a skill
    base (attack_defend) precisa existir mesmo assim, mas não deve ganhar uma
    skill de rede/web forçada sem evidência real por trás."""
    items = skills_catalog.load_all()
    keys = {(i["source"], i["external_id"]) for i in items}
    all_attack_defend_ids = {i["external_id"] for i in items if i["source"] == "attack_defend" and i["external_id"].startswith("T")}
    network_ids = {i["external_id"] for i in items if i["source"] == "network_signature" and i["external_id"].startswith("T")}
    web_ids = {i["external_id"] for i in items if i["source"] == "web_application" and i["external_id"].startswith("T")}
    assert network_ids <= all_attack_defend_ids
    assert web_ids <= all_attack_defend_ids
    assert len(all_attack_defend_ids - network_ids - web_ids) > 0, "deve existir técnica sem assinatura mapeada"
    assert keys  # sanidade


def test_correlation_brute_force_skill_requires_evidence_not_just_label():
    """Cobre o gap identificado: um rótulo de 'brute force' da fonte sozinho
    não deve virar correspondência confirmada — a skill precisa declarar a
    evidência exigida (contagem de tentativas OU reputação de IP). Relevante
    para os 3 grupos do Supervisor, então existe nos 3 buckets."""
    items = [i for i in skills_catalog.load_all() if i["external_id"] == "CSOC-001"]
    assert {i["source"] for i in items} == ALL_SOURCES
    parsed = yaml.safe_load(items[0]["yaml_content"])
    assert "T1110" in parsed["mitre"]
    assert "requires" in parsed and parsed["requires"]
    assert parsed["recommendation"]


def test_agent_threat_rules_have_real_atr_ids_and_owasp_refs():
    items = [i for i in skills_catalog.load_all() if i["source"] == "attack_defend" and i["external_id"].startswith("ATR-")]
    assert len(items) > 50
    parsed = yaml.safe_load(items[0]["yaml_content"])
    assert parsed["owasp_agentic"] or parsed["owasp_llm"]


async def test_skills_api_lists_and_filters_by_source(client, auth_headers):
    r = await client.get("/api/skills?source=web_application&limit=5", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] > 0
    assert all(item["source"] == "web_application" for item in body["items"])


async def test_skills_api_returns_yaml_for_one_skill(client, auth_headers):
    listed = await client.get("/api/skills?source=attack_defend&limit=1", headers=auth_headers)
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
    assert body["total"] > 500
