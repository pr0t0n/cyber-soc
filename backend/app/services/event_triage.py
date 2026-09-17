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


def is_compliance_noise(raw: dict[str, Any]) -> bool:
    groups = set((raw.get("rule") or {}).get("groups") or [])
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
