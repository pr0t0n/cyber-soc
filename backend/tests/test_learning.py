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
