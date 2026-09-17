"""Catálogo de skills reais baixadas de fontes públicas — nada fabricado.

Fontes e como foram obtidas (ver `scripts/fetch_skills.py` para reproduzir):
  - **attack**: técnicas MITRE ATT&CK Enterprise (STIX bundle oficial,
    mitre-attack/attack-stix-data), só técnicas de nível superior (sem
    subtécnicas), com id/nome/táticas/plataformas/descrição reais.
  - **d3fend**: contramedidas MITRE D3FEND (ontologia oficial d3fend.json),
    reconstruídas a partir da hierarquia real `rdfs:subClassOf`/`d3f:enables`
    até as 6 táticas defensivas raiz (Harden/Detect/Isolate/Deceive/Evict/Model).
  - **suricata**: regras reais do Emerging Threats Open Ruleset (sid/msg/
    classtype/protocolo/direção), categorias scan (completa) + amostra de
    malware/exploit.
  - **modsecurity**: regras reais do OWASP Core Rule Set (XSS/SQLi/RCE),
    com id/msg/tags/severidade extraídos dos arquivos `.conf` oficiais.
  - **sigma**: regras Sigma reais — amostra do repositório oficial
    (SigmaHQ/sigma, por categoria: windows/cloud/linux/network/web/...) +
    todo o SIEM-Content (abdulmyid-cyber, regras "zero-day" recentes) —
    id/título/descrição/nível/logsource/técnicas ATT&CK extraídos do YAML.
  - **agent_threats**: regras reais do Agent Threat Rules (padrão aberto
    "como Sigma, mas para agentes de IA" — MIT), cobrindo as 10 categorias
    (prompt-injection, tool-poisoning, data-poisoning, ...) com referências
    reais a OWASP LLM/Agentic e MITRE ATLAS.
  - **correlation**: NÃO é de uma fonte externa — são regras de correlação
    autorais da própria plataforma (`app/skills_data/correlation.json`),
    escritas para fechar um gap real observado: um rótulo de "brute force"/
    "port scan"/"ataque web" vindo da fonte (Wazuh/Elastic) só deve virar
    correspondência confirmada quando há evidência quantitativa (contagem de
    tentativas) OU reputação de IP já confirmada (AbuseIPDB/Shodan) — nunca só
    o rótulo. Rotulado honestamente como conteúdo interno, não como se fosse
    de um feed público.

Cada entrada vira uma "skill" servida como YAML na página Regras e usada como
base de RAG pelo motor de regras (`app/agents/`).
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

_DATA_DIR = Path(__file__).parent.parent / "skills_data"


def _yaml(data: dict) -> str:
    return yaml.dump(data, allow_unicode=True, sort_keys=False, width=100)


def _load_attack() -> list[dict]:
    items = json.loads((_DATA_DIR / "attack.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "mitre_attack_technique",
            "id": it["id"],
            "name": it["name"],
            "tactics": it["tactics"],
            "platforms": it["platforms"],
            "description": it["description"],
        }
        out.append({
            "source": "attack", "external_id": it["id"], "name": it["name"],
            "category": it["tactics"][0] if it["tactics"] else None,
            "yaml_content": _yaml(data),
            "search_text": f"{it['name']}. {it['description']}",
        })
    return out


def _load_d3fend() -> list[dict]:
    catalog = json.loads((_DATA_DIR / "d3fend.json").read_text())
    tactic_label = {
        "d3f:Harden": "Harden", "d3f:Detect": "Detect", "d3f:Isolate": "Isolate",
        "d3f:Deceive": "Deceive", "d3f:Evict": "Evict", "d3f:Model": "Model",
    }
    out = []
    for tactic_key, entries in catalog.items():
        tactic = tactic_label.get(tactic_key, tactic_key)
        for it in entries:
            data = {
                "skill": "mitre_d3fend_countermeasure",
                "id": it["id"],
                "name": it["name"],
                "tactic": tactic,
                "definition": it["definition"],
            }
            out.append({
                "source": "d3fend", "external_id": it["id"], "name": it["name"],
                "category": tactic,
                "yaml_content": _yaml(data),
                "search_text": f"{it['name']}. {it['definition']}",
            })
    return out


def _load_suricata() -> list[dict]:
    items = json.loads((_DATA_DIR / "suricata.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "suricata_signature",
            "sid": it["sid"],
            "msg": it["msg"],
            "classtype": it["classtype"],
            "action": it["action"],
            "protocol": it["protocol"],
            "direction": it["direction"],
        }
        out.append({
            "source": "suricata", "external_id": it["sid"], "name": it["msg"],
            "category": it["classtype"],
            "yaml_content": _yaml(data),
            "search_text": f"{it['msg']} ({it['classtype']}, {it['protocol']})",
        })
    return out


def _load_modsecurity() -> list[dict]:
    items = json.loads((_DATA_DIR / "modsecurity.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "modsecurity_rule",
            "id": it["id"],
            "msg": it["msg"],
            "category": it["category"],
            "severity": it["severity"],
            "tags": it["tags"],
        }
        out.append({
            "source": "modsecurity", "external_id": it["id"], "name": it["msg"],
            "category": it["category"],
            "yaml_content": _yaml(data),
            "search_text": f"{it['msg']} ({', '.join(it['tags'][:4])})",
        })
    return out


def _load_sigma() -> list[dict]:
    items = json.loads((_DATA_DIR / "sigma.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "sigma_rule",
            "id": it["id"],
            "title": it["title"],
            "level": it["level"],
            "logsource": it["logsource"],
            "mitre": it["mitre"],
            "description": it["description"],
            "source_repo": it["source_repo"],
        }
        category = (it["logsource"].get("category") or it["logsource"].get("product") or it["source_repo"])
        out.append({
            "source": "sigma", "external_id": it["id"], "name": it["title"],
            "category": category,
            "yaml_content": _yaml(data),
            "search_text": f"{it['title']}. {it['description']} mitre={','.join(it['mitre'])}",
        })
    return out


def _load_agent_threats() -> list[dict]:
    items = json.loads((_DATA_DIR / "agent_threats.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "agent_threat_rule",
            "id": it["id"],
            "title": it["title"],
            "severity": it["severity"],
            "category": it["category"],
            "description": it["description"],
            "owasp_llm": it["owasp_llm"],
            "owasp_agentic": it["owasp_agentic"],
            "mitre_atlas": it["mitre_atlas"],
            "cve": it["cve"],
        }
        out.append({
            "source": "agent_threats", "external_id": it["id"], "name": it["title"],
            "category": it["category"],
            "yaml_content": _yaml(data),
            "search_text": f"{it['title']}. {it['description']}",
        })
    return out


def _load_correlation() -> list[dict]:
    items = json.loads((_DATA_DIR / "correlation.json").read_text())
    out = []
    for it in items:
        data = {
            "skill": "cyber_soc_correlation_rule",
            "id": it["id"],
            "title": it["title"],
            "category": it["category"],
            "mitre": it["mitre"],
            "requires": it["requires"],
            "description": it["description"],
            "recommendation": it["recommendation"],
        }
        out.append({
            "source": "correlation", "external_id": it["id"], "name": it["title"],
            "category": it["category"],
            "yaml_content": _yaml(data),
            "search_text": f"{it['title']}. {it['description']} mitre={','.join(it['mitre'])}",
        })
    return out


def load_all() -> list[dict]:
    return (
        _load_attack() + _load_d3fend() + _load_suricata() + _load_modsecurity()
        + _load_sigma() + _load_agent_threats() + _load_correlation()
    )
