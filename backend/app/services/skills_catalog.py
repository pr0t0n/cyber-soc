"""Catálogo de skills reais baixadas de fontes públicas — nada fabricado.

Fontes e como foram obtidas (ver `scripts/fetch_skills.py` para reproduzir):
  - **MITRE ATT&CK**: técnicas Enterprise (STIX bundle oficial,
    mitre-attack/attack-stix-data), só técnicas de nível superior (sem
    subtécnicas), com id/nome/táticas/plataformas/descrição reais. É o EIXO
    de junção de todo o catálogo unificado abaixo.
  - **Suricata**: regras reais do Emerging Threats Open Ruleset (sid/msg/
    classtype/protocolo/direção). Suricata NÃO roda mais como processo/
    container separado na plataforma — isto é só uma amostra curada do
    ET-Open usada como fonte de skill, igual a qualquer outra. `classtype`
    é mapeado para a(s) técnica(s) MITRE correspondente(s)
    (`mitre.SURICATA_CLASSTYPE_TO_MITRE`) para juntar com o ATT&CK.
  - **ModSecurity**: regras reais do OWASP Core Rule Set (XSS/SQLi/RCE), com
    id/msg/tags/severidade extraídos dos arquivos `.conf` oficiais.
    `category` é mapeado para a técnica MITRE correspondente
    (`mitre.MODSECURITY_CATEGORY_TO_MITRE`).
  - **Sigma**: regras Sigma reais — amostra do repositório oficial
    (SigmaHQ/sigma, por categoria: windows/cloud/linux/network/web/...) +
    todo o SIEM-Content (abdulmyid-cyber, regras "zero-day" recentes) —
    id/título/descrição/nível/logsource/técnicas ATT&CK extraídos do YAML.
    Já vem com técnica(s) MITRE real no próprio dado (`mitre`), normalizada
    para a técnica-pai quando é uma subtécnica.
  - **d3fend**: contramedidas MITRE D3FEND (ontologia oficial d3fend.json),
    reconstruídas a partir da hierarquia real `rdfs:subClassOf`/`d3f:enables`
    até as 6 táticas defensivas raiz (Harden/Detect/Isolate/Deceive/Evict/
    Model). Sem cross-reference direto de técnica ATT&CK nos dados extraídos
    — fica fora da unificação por técnica, mas continua no grupo
    `attack_defend`.
  - **agent_threats**: regras reais do Agent Threat Rules (padrão aberto
    "como Sigma, mas para agentes de IA" — MIT), cobrindo as 10 categorias
    (prompt-injection, tool-poisoning, data-poisoning, ...) com referências
    reais a OWASP LLM/Agentic e MITRE ATLAS (namespace "AML.Txxxx", DIFERENTE
    do MITRE ATT&CK "Txxxx" — por isso também fica fora da unificação por
    técnica, mas continua no grupo `attack_defend`).
  - **correlation**: NÃO é de uma fonte externa — são regras de correlação
    autorais da própria plataforma (`app/skills_data/correlation.json`),
    escritas para fechar um gap real observado: um rótulo de "brute force"/
    "port scan"/"ataque web" vindo da fonte (Wazuh/Elastic) só deve virar
    correspondência confirmada quando há evidência quantitativa (contagem de
    tentativas) OU reputação de IP já confirmada (AbuseIPDB/Shodan) — nunca só
    o rótulo. Rotulado honestamente como conteúdo interno, não como se fosse
    de um feed público. Relevante para os 3 grupos do LangGraph, então entra
    nos 3.

## Unificação por técnica MITRE

Suricata, ModSecurity e Sigma eram catalogados antes como 4 listas
fragmentadas por SID/rule-id/UUID próprio de cada fonte (~1750 linhas
somadas), sem nenhuma relação direta entre si nem com a técnica ATT&CK que
de fato evidenciam — cada grupo do Supervisor via só a fonte crua, nunca
"isto tudo junto evidencia a técnica X". `_load_unified_technique_skills()`
usa as 222 técnicas do ATT&CK como eixo e funde nelas as assinaturas
Suricata/Sigma (rede) e regras ModSecurity (aplicação web) que já mapeiam
para aquela técnica, gerando no máximo 3 skills por técnica (uma por grupo
do LangGraph que a consome — `attack_defend` sempre, `network_signature` e
`web_application` só quando há assinatura real por trás). Uma técnica sem
nenhuma assinatura mapeável (ex.: a maioria das táticas de pós-exploração,
sem cobertura de rede/WAF) ainda vira skill `attack_defend` — só não ganha a
skill de rede/aplicação, porque forçar uma sem base real é pior do que não
ter.

Cada entrada vira uma "skill" servida como YAML na página Regras e usada como
base de RAG pelo motor de regras (`app/agents/`), com `source` marcando qual
dos 3 grupos do Supervisor a consome (não mais de qual fonte crua veio).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import yaml

from .mitre import MODSECURITY_CATEGORY_TO_MITRE, SURICATA_CLASSTYPE_TO_MITRE, normalize_to_parent_technique

_DATA_DIR = Path(__file__).parent.parent / "skills_data"

# Amostra máxima de assinaturas citadas no YAML/texto de busca de uma skill de
# técnica — algumas técnicas (ex.: T1071, C2) têm 150+ SIDs Suricata mapeados;
# listar todos infla o embedding sem ganho de sinal semântico. O total real
# sempre aparece no campo `total`, mesmo quando a amostra é menor.
_MAX_FACET_SAMPLE = 15


def _yaml(data: dict) -> str:
    return yaml.dump(data, allow_unicode=True, sort_keys=False, width=100)


def _load_json(name: str) -> list[dict]:
    return json.loads((_DATA_DIR / name).read_text())


def _group_suricata_by_technique(items: list[dict]) -> dict[str, list[dict]]:
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        for technique_id in SURICATA_CLASSTYPE_TO_MITRE.get(it.get("classtype") or "", []):
            by_technique[technique_id].append(it)
    return by_technique


def _group_modsecurity_by_technique(items: list[dict]) -> dict[str, list[dict]]:
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        for technique_id in MODSECURITY_CATEGORY_TO_MITRE.get(it.get("category") or "", []):
            by_technique[technique_id].append(it)
    return by_technique


def _group_sigma_by_technique(items: list[dict]) -> dict[str, list[dict]]:
    by_technique: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        for raw_id in it.get("mitre") or []:
            by_technique[normalize_to_parent_technique(raw_id)].append(it)
    return by_technique


def _load_unified_technique_skills() -> list[dict]:
    techniques = _load_json("attack.json")
    suricata_by_technique = _group_suricata_by_technique(_load_json("suricata.json"))
    modsecurity_by_technique = _group_modsecurity_by_technique(_load_json("modsecurity.json"))
    sigma_by_technique = _group_sigma_by_technique(_load_json("sigma.json"))

    out: list[dict] = []
    for tech in techniques:
        technique_id, name = tech["id"], tech["name"]
        tactic = tech["tactics"][0] if tech["tactics"] else None

        base = {
            "skill": "mitre_attack_technique",
            "id": technique_id, "name": name,
            "tactics": tech["tactics"], "platforms": tech["platforms"],
            "description": tech["description"],
        }
        out.append({
            "source": "attack_defend", "external_id": technique_id, "name": name,
            "category": tactic,
            "yaml_content": _yaml(base),
            "search_text": f"{name}. {tech['description']}",
        })

        suricata_hits = suricata_by_technique.get(technique_id, [])
        sigma_hits = sigma_by_technique.get(technique_id, [])
        if suricata_hits or sigma_hits:
            data = {
                "skill": "network_signature_for_technique",
                "technique_id": technique_id, "technique_name": name, "tactic": tactic,
                "suricata_signatures": {
                    "total": len(suricata_hits),
                    "sample": [{"sid": it["sid"], "msg": it["msg"], "classtype": it["classtype"]} for it in suricata_hits[:_MAX_FACET_SAMPLE]],
                },
                "sigma_rules": {
                    "total": len(sigma_hits),
                    "sample": [{"id": it["id"], "title": it["title"], "level": it["level"]} for it in sigma_hits[:_MAX_FACET_SAMPLE]],
                },
            }
            search_text = (
                f"{name} — assinaturas de rede reais que evidenciam esta técnica. "
                f"Suricata/ET-Open: {'; '.join(it['msg'] for it in suricata_hits[:_MAX_FACET_SAMPLE])}. "
                f"Sigma: {'; '.join(it['title'] for it in sigma_hits[:_MAX_FACET_SAMPLE])}."
            )
            out.append({
                "source": "network_signature", "external_id": technique_id, "name": name,
                "category": tactic,
                "yaml_content": _yaml(data),
                "search_text": search_text,
            })

        modsecurity_hits = modsecurity_by_technique.get(technique_id, [])
        if modsecurity_hits:
            data = {
                "skill": "web_application_rule_for_technique",
                "technique_id": technique_id, "technique_name": name, "tactic": tactic,
                "modsecurity_rules": {
                    "total": len(modsecurity_hits),
                    "sample": [{"id": it["id"], "msg": it["msg"], "category": it["category"], "severity": it["severity"]} for it in modsecurity_hits[:_MAX_FACET_SAMPLE]],
                },
            }
            search_text = (
                f"{name} — regras WAF reais que evidenciam esta técnica. "
                f"ModSecurity/OWASP CRS: {'; '.join(it['msg'] for it in modsecurity_hits[:_MAX_FACET_SAMPLE])}."
            )
            out.append({
                "source": "web_application", "external_id": technique_id, "name": name,
                "category": tactic,
                "yaml_content": _yaml(data),
                "search_text": search_text,
            })

    return out


def _load_d3fend() -> list[dict]:
    catalog = _load_json("d3fend.json")
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
                "source": "attack_defend", "external_id": it["id"], "name": it["name"],
                "category": tactic,
                "yaml_content": _yaml(data),
                "search_text": f"{it['name']}. {it['definition']}",
            })
    return out


def _load_agent_threats() -> list[dict]:
    items = _load_json("agent_threats.json")
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
            "source": "attack_defend", "external_id": it["id"], "name": it["title"],
            "category": it["category"],
            "yaml_content": _yaml(data),
            "search_text": f"{it['title']}. {it['description']}",
        })
    return out


def _load_correlation() -> list[dict]:
    """Relevante para os 3 grupos do Supervisor — uma cópia por grupo (mesmo
    conteúdo, `source` diferente), já que o conteúdo é pequeno (poucas
    dezenas de regras) e cada grupo precisa dela na própria busca RAG."""
    items = _load_json("correlation.json")
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
        yaml_content = _yaml(data)
        search_text = f"{it['title']}. {it['description']} mitre={','.join(it['mitre'])}"
        for source in ("attack_defend", "network_signature", "web_application"):
            out.append({
                "source": source, "external_id": it["id"], "name": it["title"],
                "category": it["category"],
                "yaml_content": yaml_content,
                "search_text": search_text,
            })
    return out


def load_all() -> list[dict]:
    return _load_unified_technique_skills() + _load_d3fend() + _load_agent_threats() + _load_correlation()
