"""Triagem antes do motor de regras de IA: nem todo evento do SIEM tem o
mesmo valor de sinal, e tratá-los todos com o mesmo pipeline caro (LangGraph +
RAG + LLM local, um único worker de CPU) é o que estava travando a fila em
picos reais — um scan de compliance (SCA) de um agente novo gera dezenas de
"eventos" de uma vez, nenhum deles uma ameaça, e cada um competia pelo mesmo
worker de LLM que uma tentativa de brute force real precisava.

Eventos de compliance/inventário (grupos de regra `sca`/`rootcheck` do Wazuh —
achados de auditoria de configuração, não de comportamento malicioso) tomam a
via rápida: veredito determinístico, sem chamada de IA, quase instantâneo —
liberando o único worker de LLM para eventos que podem ser um ataque de
verdade. Isso é transparente, não silencioso: o evento fica com
`rules_engine_status="informational"`, nunca "no_match" (que implica uma
análise de IA que não aconteceu)."""
from __future__ import annotations

from typing import Any

_COMPLIANCE_RULE_GROUPS = frozenset({"sca", "rootcheck"})
# "ossec" é um grupo genérico que o Wazuh adiciona a praticamente toda regra
# própria, sem sinal discriminante nenhum — sem descartá-lo antes de comparar,
# um achado real de rootcheck (`groups=["ossec","rootcheck"]`) nunca batia
# como subconjunto de `_COMPLIANCE_RULE_GROUPS` e a via rápida nunca disparava
# para o tipo de evento mais comum do próprio agente (bug real: só o `sca`
# "puro" — sem o wrapper "ossec" — estava sendo pego).
_GENERIC_WRAPPER_GROUPS = frozenset({"ossec"})


def is_compliance_noise(raw: dict[str, Any]) -> bool:
    groups = set((raw.get("rule") or {}).get("groups") or []) - _GENERIC_WRAPPER_GROUPS
    return bool(groups) and groups.issubset(_COMPLIANCE_RULE_GROUPS)


def fast_lane_verdict(event_type: str) -> dict[str, Any]:
    return {
        "matched": False,
        "matched_skills": [],
        "summary": "Achado de conformidade/inventário (SCA/rootcheck) — via rápida, sem IA.",
        "recommendation": (
            f'"{event_type}" é um achado de auditoria de configuração (SCA/rootcheck), não um '
            "comportamento observado — não passou pelo motor de IA (via rápida, para manter a "
            "análise de eventos de segurança em tempo real). Consulte a aba Raw para o achado "
            "completo; ação de hardening é da responsabilidade do time de infraestrutura."
        ),
        "groups": {},
        "fast_lane": True,
    }


def is_network_traffic(*, src_ip: str | None, dst_ip: str | None) -> bool:
    """Escopo do produto: esta plataforma analisa TRÁFEGO DE REDE, não
    telemetria de host em geral. O sinal mínimo objetivo de que um evento
    descreve alguma comunicação de rede observada é a própria fonte ter
    relatado pelo menos um IP (origem ou destino) envolvido — FIM (syscheck),
    rootcheck, SCA, inventário (syscollector), ciclo de vida do agente,
    sudo/tela bloqueada (macOS) nunca carregam IP nenhum, porque não
    descrevem tráfego algum, só estado local do host."""
    return bool(src_ip or dst_ip)


def non_network_fast_lane_verdict(event_type: str) -> dict[str, Any]:
    return {
        "matched": False,
        "matched_skills": [],
        "summary": "Telemetria de host sem sinal de rede (sem IP de origem/destino) — via rápida, sem IA.",
        "recommendation": (
            f'"{event_type}" não relata nenhum IP de origem/destino — não descreve tráfego de rede. '
            "Esta plataforma analisa tráfego de rede; achados puramente locais (inventário, FIM, "
            "compliance, ciclo de vida do agente) não passam pelo motor de IA. Consulte a aba Raw "
            "para o evento completo."
        ),
        "groups": {},
        "fast_lane": True,
    }


def deterministic_verdict(matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Formato comum do veredito da via rápida determinística — usado por
    `correlation_rules.py` (CSOC-00x, evidência quantitativa/reputação) e por
    `skill_signature_match.py` (SID Suricata / regra ModSecurity já
    catalogada) para o Supervisor e a UI (Eventos) tratarem os dois exatamente
    igual: confirmação por fato objetivo já presente no catálogo real de
    skills, nunca opinião de LLM. Cada `match` é
    `{id, mitre, title, description, recommendation}`."""
    return {
        "matched": True,
        "matched_skills": [m["id"] for m in matches],
        "summary": "Correspondência determinística confirmada: " + "; ".join(m["title"] for m in matches) + ".",
        "recommendation": " | ".join(f"{m['id']}: {m['recommendation']}" for m in matches),
        "groups": {},
        "fast_lane": True,
        "deterministic": True,
    }
