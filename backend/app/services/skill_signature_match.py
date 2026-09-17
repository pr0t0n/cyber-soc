"""Correspondência exata de assinatura (Suricata SID, regra ModSecurity)
entre o que a fonte já relatou e o catálogo real de skills baixado
(skills_data/suricata.json, skills_data/modsecurity.json) — mesmo princípio
de `_exact_id_matches` (app/agents/graph.py) para MITRE ATT&CK: se um alerta
Suricata real já veio com um `signature_id`, ou um log ModSecurity já veio
com um `id` de regra, e esse identificador está no nosso catálogo, isso é
fato objetivo (a própria ferramenta de origem já nomeou a assinatura), não
julgamento de LLM.

O catálogo de Suricata (`skills_data/suricata.json`) é uma amostra curada do
ET-Open, não o feed inteiro (ver `scripts/fetch_skills.py`) — então isto
cobre exatamente as assinaturas que já baixamos como skill, não qualquer SID
que o Suricata possa emitir. Para o resto, o evento segue para o motor de IA
normal, como qualquer correspondência não determinística."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent.parent / "skills_data"


def _load_suricata() -> dict[str, dict]:
    items = json.loads((_DATA_DIR / "suricata.json").read_text())
    return {str(it["sid"]): it for it in items}


def _load_modsecurity() -> dict[str, dict]:
    items = json.loads((_DATA_DIR / "modsecurity.json").read_text())
    return {str(it["id"]): it for it in items}


_SURICATA_BY_SID = _load_suricata()
_MODSECURITY_BY_ID = _load_modsecurity()


def _suricata_signature_id(raw: dict[str, Any]) -> str | None:
    """Wazuh repassa o registro original do eve.json em `data` quando a regra
    casada é `decoded_as: json` (ruleset padrão 0475-suricata_rules.xml) —
    `data.alert.signature_id` é o SID que o próprio Suricata atribuiu."""
    sid = ((raw.get("data") or {}).get("alert") or {}).get("signature_id")
    return str(sid) if sid else None


def _modsecurity_rule_id(raw: dict[str, Any]) -> str | None:
    """Cobre os dois formatos mais comuns de decoder ModSecurity->Wazuh:
    `data.id` (log de auditoria simples) ou `data.modsecurity.id` (decoder
    dedicado)."""
    data = raw.get("data") or {}
    rule_id = data.get("id") or (data.get("modsecurity") or {}).get("id")
    return str(rule_id) if rule_id else None


def evaluate(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Assinaturas reais que a própria fonte já relatou E que o catálogo
    reconhece — sem RAG, sem LLM. `raw` é o payload bruto do evento
    (`Event.raw`)."""
    matches: list[dict[str, Any]] = []

    sid = _suricata_signature_id(raw)
    skill = _SURICATA_BY_SID.get(sid) if sid else None
    if skill:
        matches.append({
            "id": sid, "mitre": [],
            "title": skill["msg"],
            "description": (
                f"Assinatura Suricata/ET-Open catalogada: {skill['msg']} "
                f"(classtype={skill['classtype']}, SID {sid})."
            ),
            "recommendation": (
                f"Confirmar bloqueio de rede para a assinatura '{skill['msg']}' (SID {sid}) "
                "e revisar o host/IP envolvido."
            ),
        })

    rule_id = _modsecurity_rule_id(raw)
    skill = _MODSECURITY_BY_ID.get(rule_id) if rule_id else None
    if skill:
        matches.append({
            "id": rule_id, "mitre": [],
            "title": skill["msg"],
            "description": (
                f"Regra ModSecurity/OWASP CRS catalogada: {skill['msg']} "
                f"(categoria={skill['category']}, severidade={skill['severity']})."
            ),
            "recommendation": (
                f"Confirmar bloqueio da regra ModSecurity {rule_id} ('{skill['msg']}') no WAF "
                "e revisar logs da aplicação por sinais de exploração bem-sucedida."
            ),
        })

    return matches
