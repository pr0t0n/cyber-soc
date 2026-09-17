"""Bootstrap: admin inicial + catálogo real de skills (sem dados mockados).
Idempotente — cada parte só roda se ainda não houver o que criaria."""
import asyncio

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth.security import hash_password
from .config import settings
from .db import SessionLocal
from .models import Event, Skill, User
from .services import skills_catalog
from .services.rag import backfill_embeddings
from .services.rules_engine import run_rules_engine_for_event


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


async def _ensure_skills(db: AsyncSession) -> tuple[int, int]:
    """Upsert por (source, external_id) — não só "insere se faltar": conteúdo
    autoral (`correlation`) muda com frequência normal de desenvolvimento, e
    uma skill que existe mas está desatualizada silenciosamente nunca se
    corrigiria sozinha. Conteúdo alterado limpa o embedding para o backfill
    reidratar (rag.py) — nunca serve uma busca semântica sobre texto velho."""
    existing = {(s.source, s.external_id): s for s in (await db.execute(select(Skill))).scalars().all()}
    installed = updated = 0
    for entry in skills_catalog.load_all():
        key = (entry["source"], entry["external_id"])
        row = existing.get(key)
        if row is None:
            db.add(Skill(**entry))
            installed += 1
            continue
        if row.yaml_content != entry["yaml_content"] or row.search_text != entry["search_text"]:
            row.name = entry["name"]
            row.category = entry["category"]
            row.yaml_content = entry["yaml_content"]
            row.search_text = entry["search_text"]
            row.embedding = None
            updated += 1
    await db.commit()
    return installed, updated


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


async def _requeue_stuck_events(db: AsyncSession) -> int:
    """`BackgroundTasks` do FastAPI só existe na memória do processo que a
    agendou — um restart (deploy, crash, `docker compose up --build`) perde
    silenciosamente qualquer evento ainda `pending`/`analyzing`, que fica
    "travado" para sempre sem isso. Reagenda no boot; refazer a análise do
    zero é seguro (idempotente do ponto de vista de negócio) mesmo que o
    evento já tivesse progresso parcial de uma tentativa anterior."""
    ids = (
        await db.execute(select(Event.id).where(Event.rules_engine_status.in_(("pending", "analyzing"))))
    ).scalars().all()
    for event_id in ids:
        asyncio.create_task(run_rules_engine_for_event(event_id))
    return len(ids)


async def bootstrap() -> None:
    async with SessionLocal() as db:
        await _ensure_admin(db)
        installed, updated = await _ensure_skills(db)
        await db.commit()
        if installed:
            print(f"[bootstrap] {installed} skills reais carregadas (ATT&CK/D3FEND/Suricata/ModSecurity).")
        if updated:
            print(f"[bootstrap] {updated} skill(s) com conteúdo atualizado (embedding será regenerado).")
        if settings.rules_engine_enabled:
            requeued = await _requeue_stuck_events(db)
            if requeued:
                print(f"[bootstrap] {requeued} evento(s) pending/analyzing reagendado(s) após restart.")
    if settings.rules_engine_enabled:
        asyncio.create_task(_backfill_embeddings_forever())
