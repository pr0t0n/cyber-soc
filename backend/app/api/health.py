import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    try:
        await db.execute(text("SELECT 1"))
        db_status = "up"
    except Exception:  # noqa: BLE001
        db_status = "down"
    return {"status": "ok", "database": db_status}


@router.get("/health/diag")
async def health_diag(stacks_for: str | None = None) -> dict:
    """Diagnóstico temporário (achado real de teste de carga: pool inteiro
    ficando "idle in transaction") — nunca depende de `get_db`, senão fica
    tão preso quanto o resto assim que o pool esgota. `stacks_for` (opcional):
    substring do qualname da coroutine — devolve o frame Python exato onde
    cada task correspondente está suspensa (`task.get_stack()`), pra achar
    a linha travada sem adivinhar por cima de pg_stat_activity."""
    from ..services import rules_engine

    tasks = asyncio.all_tasks()
    by_name: dict[str, int] = {}
    stacks: list[str] = []
    for t in tasks:
        coro = t.get_coro()
        name = getattr(coro, "__qualname__", type(coro).__name__)
        by_name[name] = by_name.get(name, 0) + 1
        if stacks_for and stacks_for in name:
            frames = t.get_stack(limit=8)
            stacks.append(
                " -> ".join(f"{f.f_code.co_filename.split('/')[-1]}:{f.f_lineno}:{f.f_code.co_name}" for f in frames)
            )
    return {
        "total_tasks": len(tasks),
        "tasks_by_coro": by_name,
        "ingest_processing_sem_value": rules_engine._INGEST_PROCESSING_CONCURRENCY._value,
        "analysis_sem_value": rules_engine._ANALYSIS_CONCURRENCY._value,
        **({"stacks": stacks} if stacks_for else {}),
    }
