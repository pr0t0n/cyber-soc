"""Aprendizado incremental leve — ver `LearnedPattern` para o porquê. Duas
operações: `record_confirmation` (chamada depois de todo veredito REAL da IA,
nunca de um degradado) e `lookup` (chamada ANTES de acionar o LLM, junto das
outras vias rápidas determinísticas)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import advisory_lock
from ..models import LearnedPattern

PROMOTION_THRESHOLD = 3


async def record_confirmation(db: AsyncSession, pattern_key: str, verdict: dict[str, Any]) -> None:
    """Incrementa (ou cria) o padrão para este `Event.type` com o veredito
    mais recente — a recomendação/técnica fica sempre com a confirmação mais
    nova, a contagem só cresce.

    `advisory_lock` (app/db.py) trava por `pattern_key` ANTES do SELECT que
    decide criar-ou-atualizar — achado real de teste de carga: eventos do
    MESMO `Event.type` confirmados em paralelo (comum sob rajada) liam "ainda
    não existe padrão" ao mesmo tempo e cada um tentava criar a linha, a
    segunda derrubando com violação de unicidade em `pattern_key`."""
    await advisory_lock(db, pattern_key)
    row = (
        await db.execute(select(LearnedPattern).where(LearnedPattern.pattern_key == pattern_key))
    ).scalar_one_or_none()
    mitre = list((verdict.get("groups") or {}).get("attack_defend", {}).get("skills") or [])
    matched_skills = sorted(verdict.get("matched_skills") or [])
    if row is None:
        row = LearnedPattern(
            pattern_key=pattern_key, mitre=mitre, matched_skills=matched_skills,
            recommendation=verdict.get("recommendation"), summary=verdict.get("summary"), confirmations=1,
        )
        db.add(row)
    elif sorted(row.matched_skills or []) == matched_skills:
        # Confirmação CONSISTENTE com o que já foi visto pra este `pattern_key`
        # — conta de verdade pra promoção.
        row.confirmations += 1
        row.mitre = mitre or row.mitre
        row.recommendation = verdict.get("recommendation") or row.recommendation
        row.summary = verdict.get("summary") or row.summary
        if row.confirmations >= PROMOTION_THRESHOLD:
            row.promoted = True
    else:
        # Achado real de teste de carga: o mesmo `Event.type` confirmado com
        # skills DIFERENTES em execuções sucessivas (ex.: "T1595 dessa vez,
        # ATR-2026-00080 da próxima" pro mesmo tipo de alerta) é sinal de que
        # o LLM não está convergindo num veredito real pra este padrão —
        # alucinação/ambiguidade, não um padrão estável — e promover
        # baseado nisso vira um falso positivo permanente (via rápida sem
        # LLM nenhum a partir daí). Reinicia a contagem em vez de somar
        # confirmações que nunca concordaram entre si.
        row.confirmations = 1
        row.matched_skills = matched_skills
        row.mitre = mitre
        row.recommendation = verdict.get("recommendation")
        row.summary = verdict.get("summary")
        row.promoted = False
    await db.commit()


async def apply_analyst_feedback(db: AsyncSession, *, pattern_key: str, matched_skills: list[str], verdict: str | None) -> bool:
    """Fecha o loop que `record_confirmation` sozinho não fecha: até aqui, um
    padrão só se confirma através da própria IA concordando consigo mesma —
    nunca reage a um humano revisando um evento (`Event.analyst_verdict`,
    `PATCH /api/events/{id}/verdict`). Um analista marcando `false_positive`
    pra um evento cuja skill/tipo já virou via rápida promovida é prova
    direta de que aquela via rápida está errada — despromove na hora, em vez
    de esperar uma auditoria manual descobrir depois (achado real: uma
    auditoria retroativa já precisou corrigir 166 de 185 incidentes assim,
    ver `analise-mercado-agent-soc-vs-capacidade-atual.md`).

    Só reage a `false_positive` de propósito: `true_positive`/`true_negative`
    já é o que o padrão promovido previa (nada a corrigir), e
    `false_negative` (ameaça real que passou) não tem nenhum padrão
    PROMOVIDO por trás pra despromover — é ausência de detecção, um problema
    de cobertura, não de um padrão aprendido errado.

    Retorna `True` quando de fato despromoveu algo (útil pro chamador logar/
    expor na resposta da API)."""
    if verdict != "false_positive":
        return False
    await advisory_lock(db, pattern_key)
    row = (
        await db.execute(select(LearnedPattern).where(LearnedPattern.pattern_key == pattern_key))
    ).scalar_one_or_none()
    if row is None or not row.promoted:
        return False
    # Só despromove se a skill que a revisão humana contesta é a MESMA que
    # este padrão representa — um falso positivo reportado pra uma skill
    # diferente da que o padrão promovido confirma não é evidência contra
    # ESTE padrão específico.
    if not (set(row.matched_skills or []) & set(matched_skills or [])):
        return False
    row.promoted = False
    row.confirmations = 0
    await db.commit()
    return True


async def lookup(db: AsyncSession, pattern_key: str) -> LearnedPattern | None:
    """Só retorna um padrão já PROMOVIDO (confirmações suficientes) — as
    primeiras `PROMOTION_THRESHOLD - 1` ocorrências de um tipo de alerta novo
    sempre passam pela IA de verdade; a via rápida só nasce depois de a
    plataforma já ter visto o mesmo veredito se repetir, nunca de uma
    confirmação isolada (evitaria generalizar de um caso só)."""
    row = (
        await db.execute(
            select(LearnedPattern).where(LearnedPattern.pattern_key == pattern_key, LearnedPattern.promoted.is_(True))
        )
    ).scalar_one_or_none()
    return row


def learned_verdict(pattern: LearnedPattern) -> dict[str, Any]:
    return {
        "matched": True,
        "matched_skills": pattern.matched_skills,
        "summary": f"Padrão aprendido (confirmado {pattern.confirmations}x pela IA anteriormente): {pattern.summary or ''}".strip(),
        "recommendation": pattern.recommendation,
        "mitre": pattern.mitre,
        "groups": {},
        "fast_lane": True,
        "deterministic": False,
        "learned": True,
    }
