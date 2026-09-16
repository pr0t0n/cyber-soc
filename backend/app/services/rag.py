"""RAG de hidratação: embeddings reais (Ollama `nomic-embed-text`) sobre o
catálogo de skills, buscados por similaridade (pgvector) — é isso que os
grupos do motor de regras (`app/agents/graph.py`) consultam via MCP para
decidir se um evento casa com uma skill real."""
from __future__ import annotations

import asyncio

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Skill


async def embed_text(content: str) -> list[float] | None:
    url = settings.llm_base_url.rstrip("/") + "/embeddings"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(url, json={"model": settings.embed_model, "input": content})
        if r.status_code >= 400:
            return None
        data = r.json()
        return data["data"][0]["embedding"]
    except (httpx.HTTPError, KeyError, IndexError):
        return None


async def backfill_embeddings(db: AsyncSession, batch_size: int = 25) -> int:
    """Gera embeddings para skills que ainda não têm (idempotente, retomável).
    Uma pequena pausa entre lotes deixa o Ollama local (CPU, um único worker)
    respirar para o motor de regras (`app/agents/graph.py`), que é
    interativo — a hidratação em massa pode esperar mais um pouco."""
    done = 0
    while True:
        rows = (
            await db.execute(select(Skill).where(Skill.embedding.is_(None)).limit(batch_size))
        ).scalars().all()
        if not rows:
            break
        for skill in rows:
            vec = await embed_text(skill.search_text)
            if vec:
                skill.embedding = vec
                done += 1
        await db.commit()
        await asyncio.sleep(2)
    return done


async def search_skills(db: AsyncSession, query: str, source: str | None = None, limit: int = 5) -> list[dict]:
    """Busca por similaridade de embedding — RAG real, não substring match.
    Sem embeddings prontos ainda (backfill em andamento), degrada para uma
    busca textual simples em vez de falhar."""
    vec = await embed_text(query)
    if vec is None:
        return await _fallback_text_search(db, query, source, limit)

    stmt = select(Skill).where(Skill.embedding.is_not(None))
    if source:
        stmt = stmt.where(Skill.source == source)
    stmt = stmt.order_by(Skill.embedding.cosine_distance(vec)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return await _fallback_text_search(db, query, source, limit)
    return [
        {"source": s.source, "external_id": s.external_id, "name": s.name, "category": s.category, "yaml": s.yaml_content}
        for s in rows
    ]


async def _fallback_text_search(db: AsyncSession, query: str, source: str | None, limit: int) -> list[dict]:
    stmt = select(Skill).where(Skill.search_text.ilike(f"%{query}%"))
    if source:
        stmt = stmt.where(Skill.source == source)
    rows = (await db.execute(stmt.limit(limit))).scalars().all()
    return [
        {"source": s.source, "external_id": s.external_id, "name": s.name, "category": s.category, "yaml": s.yaml_content}
        for s in rows
    ]
