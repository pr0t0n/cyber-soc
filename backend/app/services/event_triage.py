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
