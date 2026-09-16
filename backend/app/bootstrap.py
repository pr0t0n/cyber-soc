"""Bootstrap: admin inicial + catálogo real de skills (sem dados mockados).
Idempotente — cada parte só roda se ainda não houver o que criaria."""
import asyncio

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth.security import hash_password
from .config import settings
from .db import SessionLocal
from .models import Skill, User
from .services import skills_catalog
from .services.rag import backfill_embeddings


async def _ensure_admin(db: AsyncSession) -> None:
    existing = (await db.execute(select(User.id).limit(1))).first()
    if existing:
        return
    db.add(
        User(
            name=settings.bootstrap_admin_name,
            email=settings.bootstrap_admin_email,
            role="admin",
            status="ativo",
            password_hash=hash_password(settings.bootstrap_admin_password),
        )
    )


async def _ensure_skills(db: AsyncSession) -> int:
    """Idempotente por (source, external_id) — não por contagem total, para que
    novas fontes adicionadas depois (ex.: sigma, agent_threats) sejam
    carregadas em instalações já semeadas, sem duplicar as existentes."""
    existing = set(
        (await db.execute(select(Skill.source, Skill.external_id))).all()
    )
    installed = 0
    for entry in skills_catalog.load_all():
        key = (entry["source"], entry["external_id"])
        if key in existing:
            continue
        db.add(Skill(**entry))
        existing.add(key)
        installed += 1
    await db.commit()
    return installed


async def _backfill_embeddings_forever() -> None:
    """Roda em background após o startup — nunca atrasa o health check.
    Ollama pode não estar pronto ainda (modelo ainda não baixado); tenta de
    novo em vez de desistir."""
    for _ in range(60):
        async with SessionLocal() as db:
            try:
                done = await backfill_embeddings(db)
                if done or (await db.execute(select(func.count(Skill.id)).where(Skill.embedding.is_(None)))).scalar() == 0:
                    return
            except Exception:  # noqa: BLE001 — nunca derruba o processo da API
                pass
        await asyncio.sleep(10)


async def bootstrap() -> None:
    async with SessionLocal() as db:
        await _ensure_admin(db)
        installed = await _ensure_skills(db)
        await db.commit()
        if installed:
            print(f"[bootstrap] {installed} skills reais carregadas (ATT&CK/D3FEND/Suricata/ModSecurity).")
    if settings.rules_engine_enabled:
        asyncio.create_task(_backfill_embeddings_forever())
