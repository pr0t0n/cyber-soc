"""Avaliação determinística das regras de correlação internas
(`skills_data/correlation.json`, CSOC-00x) — hoje elas só existiam como texto
para o RAG/LLM "opinar" sobre, o que faz até o caso mais óbvio (IP já
confirmado malicioso pelo AbuseIPDB batendo numa porta de força bruta)
esperar minutos na fila do Ollama (CPU, um único worker) atrás de grupos
sequenciais + embeddings + chamadas de LLM.

Os campos que os `requires` de cada regra descrevem (porta de destino,
`hit_count`, `correlated_count`, reputação de IP) já são calculados de forma
barata e determinística ANTES do motor de IA rodar:
  - porta/protocolo/reputação de IP: `app/services/threat_intel.py` no ingest;
  - `correlated_count`: `app/services/correlation.py`, logo no início de
    `run_rules_engine_for_event`.

Então, assim como `event_triage.py` tira ruído de compliance da fila da IA,
este módulo confirma (ou não) as regras CSOC-00x direto contra esses campos —
sem RAG, sem embedding, sem LLM. Isso é o que faz "analisar IP, tipo de
tráfego e correlação" acontecer em milissegundos, e não minutos: a IA só é
acionada para o que sobra — os casos de fato ambíguos, sem porta/volume/
reputação que já resolvam a pergunta."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import event_triage

_DATA_PATH = Path(__file__).parent.parent / "skills_data" / "correlation.json"
_RULES: list[dict] = json.loads(_DATA_PATH.read_text())
_BY_ID: dict[str, dict] = {r["id"]: r for r in _RULES}

# Nota de risco a partir da qual `threat_intel.score_traffic` já classifica o
# IP como referência objetiva de threat intel real — cobre tanto AbuseIPDB
# >= 80 (citado explicitamente nas regras) quanto os bônus fixos que
# `score_traffic` aplica para nó Tor / tags de risco do Shodan (ambos 70):
# são fatos de reputação, não uma inferência do LLM.
_CONFIRMED_MALICIOUS_SCORE = 70

# Padrões objetivos de SQLi/XSS/RCE — a mesma classe de assinatura que um WAF
# (ModSecurity/OWASP CRS) já aplicaria; usados aqui só para o "any_of" de
# CSOC-003 não depender de LLM quando o payload já é uma evidência clara.
_ATTACK_PAYLOAD_RE = re.compile(
    r"(?i)union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|<script|javascript:|onerror\s*=|"
    r";\s*cat\s+/etc/passwd|wget\s+https?://|curl\s+https?://|powershell\s+-enc|xp_cmdshell|"
    r"drop\s+table|sleep\(\d"
)
_WEB_PORTS = {"80", "443", "8080", "8443"}


def _port_int(event: dict[str, Any]) -> int | None:
    port = event.get("dst_port")
    try:
        return int(port) if port is not None else None
    except (TypeError, ValueError):
        return None


def _confirmed_malicious(assessment: dict[str, Any]) -> bool:
    return int(assessment.get("risk_score") or 0) >= _CONFIRMED_MALICIOUS_SCORE


def _volume_confirms(event: dict[str, Any], *, threshold: int = 5) -> bool:
    hit_count = event.get("hit_count")
    correlated = event.get("correlated_count")
    return (hit_count is not None and hit_count >= threshold) or (correlated is not None and correlated >= threshold)


def _has_attack_payload(event: dict[str, Any]) -> bool:
    text = " ".join(str(event.get(k) or "") for k in ("behavior", "type"))
    return bool(_ATTACK_PAYLOAD_RE.search(text))


def _match_csoc_001(event: dict[str, Any], assessment: dict[str, Any]) -> bool:
    """Força bruta: porta de autenticação exposta (`requires.target_port_in`)
    + (volume relatado/correlacionado OU reputação já confirmada)."""
    if _port_int(event) not in _BY_ID["CSOC-001"]["requires"]["target_port_in"]:
        return False
    return _volume_confirms(event) or _confirmed_malicious(assessment)


def _match_csoc_002(event: dict[str, Any], assessment: dict[str, Any]) -> bool:
    """Varredura: volume correlacionado da mesma origem OU reputação já
    confirmada — sem porta específica, por natureza (múltiplos destinos)."""
    correlated = event.get("correlated_count")
    return (correlated is not None and correlated >= 5) or _confirmed_malicious(assessment)


def _match_csoc_003(event: dict[str, Any], assessment: dict[str, Any]) -> bool:
    """Ataque de aplicação web: só avalia em tráfego de fato web (porta/
    protocolo HTTP(S)) — sem esse portão, um IP malicioso batendo numa porta
    qualquer (ex.: SSH) casaria "ataque web" por reputação sozinha, o que o
    JSON não pretende (a regra é sobre payload web + reputação, não reputação
    isolada de qualquer tráfego)."""
    port = event.get("dst_port")
    protocol = (event.get("protocol") or "").upper()
    if port not in _WEB_PORTS and protocol not in ("HTTP", "HTTPS"):
        return False
    return _has_attack_payload(event) or _confirmed_malicious(assessment)


def _match_csoc_004(event: dict[str, Any], assessment: dict[str, Any]) -> bool:
    """Beacon de C2: porta historicamente associada a C2/RAT/Tor + reputação
    já confirmada — nunca porta isolada (ruído demais) nem reputação isolada
    (sem relação com o tráfego observado)."""
    if _port_int(event) not in _BY_ID["CSOC-004"]["requires"]["target_port_in"]:
        return False
    return _confirmed_malicious(assessment)


_MATCHERS = {
    "CSOC-001": _match_csoc_001,
    "CSOC-002": _match_csoc_002,
    "CSOC-003": _match_csoc_003,
    "CSOC-004": _match_csoc_004,
}


def evaluate(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Quais regras CSOC-00x casam por evidência estrutural pura — sem RAG,
    sem LLM. `event` é o mesmo payload plano montado em
    `rules_engine.run_rules_engine_for_event` (tem `dst_port`, `hit_count`,
    `correlated_count`, `enrichment.assessment`, `behavior`, `type`)."""
    assessment = ((event.get("enrichment") or {}).get("assessment")) or {}
    matches = []
    for rule_id, matcher in _MATCHERS.items():
        if matcher(event, assessment):
            rule = _BY_ID[rule_id]
            matches.append({
                "id": rule_id, "mitre": rule["mitre"], "title": rule["title"],
                "description": rule["description"], "recommendation": rule["recommendation"],
            })
    return matches


def fast_lane_verdict(event: dict[str, Any]) -> dict[str, Any] | None:
    """Veredito pronto para `Event.rules_engine_verdict`, ou `None` quando
    nenhuma regra casa por fato (nesse caso o evento segue para o motor de IA
    normal — via rápida não é um "sempre libera", é um "libera quando já dá
    para confirmar sem opinião de LLM")."""
    matches = evaluate(event)
    if not matches:
        return None
    return event_triage.deterministic_verdict(matches)
