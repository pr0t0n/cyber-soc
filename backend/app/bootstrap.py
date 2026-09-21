"""Bootstrap: admin inicial + catálogo real de skills (sem dados mockados).
Idempotente — cada parte só roda se ainda não houver o que criaria."""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth.security import hash_password
from .config import settings
from .db import SessionLocal
from .models import Event, Skill, User
from .services import skills_catalog
from .services.asm import refresh_exposed_assets
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


async def _ensure_skills(db: AsyncSession) -> tuple[int, int, int]:
    """Upsert por (source, external_id) — não só "insere se faltar": conteúdo
    autoral (`correlation`) muda com frequência normal de desenvolvimento, e
    uma skill que existe mas está desatualizada silenciosamente nunca se
    corrigiria sozinha. Conteúdo alterado limpa o embedding para o backfill
    reidratar (rag.py) — nunca serve uma busca semântica sobre texto velho.
    Também remove skills cuja chave não existe mais no catálogo gerado — sem
    isso, uma mudança de fonte/organização (ex.: `source` "suricata" virando
    "network_signature") deixaria as linhas antigas órfãs para sempre na
    tabela, aparecendo na página Regras junto do catálogo novo."""
    existing = {(s.source, s.external_id): s for s in (await db.execute(select(Skill))).scalars().all()}
    seen_keys: set[tuple[str, str]] = set()
    installed = updated = 0
    for entry in skills_catalog.load_all():
        key = (entry["source"], entry["external_id"])
        seen_keys.add(key)
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
    removed = 0
    for key, row in existing.items():
        if key not in seen_keys:
            await db.delete(row)
            removed += 1
    await db.commit()
    return installed, updated, removed


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


_ORPHAN_SWEEP_INTERVAL_SECONDS = 300.0
_ORPHAN_THRESHOLD_MINUTES = 25
"""Folga sobre `_EVENT_PROCESSING_HARD_CEILING_SECONDS` (20min) em rules_engine.py:
nenhum evento legítimo fica pending/analyzing por mais tempo que o teto, então um
achado mais velho que isso é sempre órfão — nunca trabalho real em andamento."""


async def _sweep_orphaned_events_forever() -> None:
    """Rede de segurança independente de `run_rules_engine_for_event`: mesmo com o
    teto de tempo e o handler de exceção que marca o evento como falha técnica, a
    PRÓPRIA escrita de limpeza pode falhar silenciosamente (ex.: pool de conexões
    também esgotado no exato momento da falha), deixando o evento "analyzing" para
    sempre sem nenhum erro visível — observado ao vivo em cargas de ~80 eventos,
    onde uma pequena fração (5-7) ficava travada mesmo com o teto em vigor. Varre
    periodicamente por pending/analyzing mais velhos que a folga e reagenda."""
    while True:
        await asyncio.sleep(_ORPHAN_SWEEP_INTERVAL_SECONDS)
        try:
            threshold = datetime.now(timezone.utc) - timedelta(minutes=_ORPHAN_THRESHOLD_MINUTES)
            async with SessionLocal() as db:
                ids = (
                    await db.execute(
                        select(Event.id).where(
                            Event.rules_engine_status.in_(("pending", "analyzing")),
                            Event.received_at < threshold,
                        )
                    )
                ).scalars().all()
            for event_id in ids:
                asyncio.create_task(run_rules_engine_for_event(event_id))
            if ids:
                print(f"[bootstrap] {len(ids)} evento(s) órfão(s) (travado(s) há mais de {_ORPHAN_THRESHOLD_MINUTES}min) reagendado(s).")
        except Exception:  # noqa: BLE001 — nunca derruba o processo da API
            pass


_ASM_SWEEP_INTERVAL_SECONDS = 6 * 3600.0
"""Não precisa ser frequente: Shodan indexa a internet em dias/semanas, não
minutos — reconsultar mais rápido que isso só queima cota de API sem
nenhum dado novo pra mostrar. `refresh_exposed_assets` já pula IP com cache
ainda válido (`settings.intel_cache_ttl_hours`), então rodar de novo é
sempre seguro (idempotente), só caro à toa se rodar rápido demais."""


async def _asm_sweep_forever() -> None:
    """Mesmo padrão de `_sweep_orphaned_events_forever`: nunca atrasa o
    startup, nunca derruba o processo por causa de uma falha de rede/API
    externa."""
    while True:
        await asyncio.sleep(_ASM_SWEEP_INTERVAL_SECONDS)
        try:
            async with SessionLocal() as db:
                checked = await refresh_exposed_assets(db)
            if checked:
                print(f"[bootstrap] ASM: {checked} IP(s) público(s) consultado(s) no Shodan.")
        except Exception:  # noqa: BLE001 — nunca derruba o processo da API
            pass


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
        installed, updated, removed = await _ensure_skills(db)
        await db.commit()
        if installed:
            print(f"[bootstrap] {installed} skills reais carregadas (ATT&CK/D3FEND/Suricata/ModSecurity).")
        if updated:
            print(f"[bootstrap] {updated} skill(s) com conteúdo atualizado (embedding será regenerado).")
        if removed:
            print(f"[bootstrap] {removed} skill(s) órfã(s) removida(s) (fonte/organização mudou).")
        if settings.rules_engine_enabled:
            requeued = await _requeue_stuck_events(db)
            if requeued:
                print(f"[bootstrap] {requeued} evento(s) pending/analyzing reagendado(s) após restart.")
    if settings.rules_engine_enabled:
        asyncio.create_task(_backfill_embeddings_forever())
        asyncio.create_task(_sweep_orphaned_events_forever())
        asyncio.create_task(_asm_sweep_forever())
