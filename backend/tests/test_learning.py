"""Aprendizado incremental (app/services/learning.py) — a plataforma promove
um `Event.type` para via rápida só depois de ver a IA confirmar o MESMO
veredito repetidas vezes, nunca de uma confirmação isolada."""
from app.db import SessionLocal
from app.services import learning

_VERDICT = {
    "matched": True, "matched_skills": ["T1110"], "summary": "Confirmado.",
    "recommendation": "Bloquear.", "groups": {"attack_defend": {"skills": ["T1110"]}},
}


async def test_pattern_is_not_promoted_before_threshold():
    async with SessionLocal() as db:
        await learning.record_confirmation(db, "SSHD brute force", _VERDICT)
        assert await learning.lookup(db, "SSHD brute force") is None


async def test_pattern_is_promoted_after_threshold_confirmations():
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)
        pattern = await learning.lookup(db, "SSHD brute force")
        assert pattern is not None
        assert pattern.confirmations == learning.PROMOTION_THRESHOLD
        assert pattern.mitre == ["T1110"]


async def test_unrelated_pattern_key_stays_unpromoted():
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)
        assert await learning.lookup(db, "Outro tipo de alerta") is None


async def test_learned_verdict_is_a_fast_lane_shaped_match():
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)
        pattern = await learning.lookup(db, "SSHD brute force")
        verdict = learning.learned_verdict(pattern)
        assert verdict["matched"] is True
        assert verdict["mitre"] == ["T1110"]
        assert verdict["learned"] is True
        assert "confirmado" in verdict["summary"].lower()


async def test_inconsistent_confirmations_reset_the_counter_instead_of_promoting():
    """Achado real de teste de carga: o mesmo `Event.type` confirmado com
    skills DIFERENTES em execuções sucessivas (LLM não convergindo — sinal
    de alucinação/ambiguidade, não de padrão estável) chegou a acumular 3
    "confirmações" e ser promovido — virando via rápida sem LLM pra um
    falso positivo permanente. Uma confirmação que diverge da anterior tem
    que reiniciar a contagem, nunca somar."""
    verdict_a = {
        "matched": True, "matched_skills": ["T1595"], "summary": "Scan.",
        "recommendation": "Bloquear.", "groups": {"attack_defend": {"skills": ["T1595"]}},
    }
    verdict_b = {
        "matched": True, "matched_skills": ["ATR-2026-00080"], "summary": "Prompt injection?",
        "recommendation": "Investigar.", "groups": {"attack_defend": {"skills": ["ATR-2026-00080"]}},
    }
    async with SessionLocal() as db:
        await learning.record_confirmation(db, "Encoded PowerShell execution", verdict_a)
        await learning.record_confirmation(db, "Encoded PowerShell execution", verdict_a)
        # Terceira confirmação diverge da anterior — reinicia, não promove.
        await learning.record_confirmation(db, "Encoded PowerShell execution", verdict_b)
        assert await learning.lookup(db, "Encoded PowerShell execution") is None

        # Só promove depois de PROMOTION_THRESHOLD confirmações CONSISTENTES
        # a partir da divergência (a que divergiu já reiniciou pra 1).
        await learning.record_confirmation(db, "Encoded PowerShell execution", verdict_b)
        await learning.record_confirmation(db, "Encoded PowerShell execution", verdict_b)
        pattern = await learning.lookup(db, "Encoded PowerShell execution")
        assert pattern is not None
        assert pattern.matched_skills == ["ATR-2026-00080"]


async def test_analyst_false_positive_demotes_a_promoted_pattern():
    """Fecha o loop que record_confirmation sozinho não fecha: até aqui, um
    padrão só se confirmava através da própria IA — nunca reagia a um
    humano revisando um evento."""
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)
        assert await learning.lookup(db, "SSHD brute force") is not None

        demoted = await learning.apply_analyst_feedback(
            db, pattern_key="SSHD brute force", matched_skills=["T1110"], verdict="false_positive",
        )
        assert demoted is True
        assert await learning.lookup(db, "SSHD brute force") is None


async def test_analyst_feedback_ignores_verdicts_other_than_false_positive():
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)

        for verdict in ("true_positive", "true_negative", "false_negative", None):
            demoted = await learning.apply_analyst_feedback(
                db, pattern_key="SSHD brute force", matched_skills=["T1110"], verdict=verdict,
            )
            assert demoted is False
        assert await learning.lookup(db, "SSHD brute force") is not None


async def test_analyst_feedback_does_not_demote_when_disputed_skill_does_not_match_the_pattern():
    """Um falso positivo reportado pra uma skill DIFERENTE da que o padrão
    promovido representa não é evidência contra ESTE padrão."""
    async with SessionLocal() as db:
        for _ in range(learning.PROMOTION_THRESHOLD):
            await learning.record_confirmation(db, "SSHD brute force", _VERDICT)  # T1110

        demoted = await learning.apply_analyst_feedback(
            db, pattern_key="SSHD brute force", matched_skills=["T1595"], verdict="false_positive",
        )
        assert demoted is False
        assert await learning.lookup(db, "SSHD brute force") is not None


async def test_analyst_feedback_is_a_noop_when_pattern_was_never_promoted():
    async with SessionLocal() as db:
        await learning.record_confirmation(db, "SSHD brute force", _VERDICT)  # só 1 confirmação, não promovido

        demoted = await learning.apply_analyst_feedback(
            db, pattern_key="SSHD brute force", matched_skills=["T1110"], verdict="false_positive",
        )
        assert demoted is False


async def test_analyst_feedback_is_a_noop_for_unknown_pattern_key():
    async with SessionLocal() as db:
        demoted = await learning.apply_analyst_feedback(
            db, pattern_key="Tipo nunca visto", matched_skills=["T1110"], verdict="false_positive",
        )
        assert demoted is False
