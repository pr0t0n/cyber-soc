"""Página Regras: skills reais, unificadas por técnica MITRE ATT&CK
(Suricata/ModSecurity/Sigma fundidos na técnica que evidenciam, mais
D3FEND/Agent Threat Rules/correlação interna — ver
app/services/skills_catalog.py) em YAML — a mesma base usada como RAG pelo
motor de regras (app/agents/)."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Skill, User
from ..models.skill import SKILL_SOURCES

router = APIRouter(prefix="/api/skills", tags=["skills"])


@router.get("/sources")
async def sources(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    rows = (await db.execute(select(Skill.source, func.count(Skill.id)).group_by(Skill.source))).all()
    counts = {s: int(c) for s, c in rows}
    embedded = (await db.execute(select(func.count(Skill.id)).where(Skill.embedding.is_not(None)))).scalar() or 0
    total = sum(counts.values())
    return {
        "sources": [{"source": s, "count": counts.get(s, 0)} for s in SKILL_SOURCES],
        "total": total,
        "embedded": embedded,
        "hydration_pct": round(embedded * 100 / total, 1) if total else 0.0,
    }


@router.get("")
async def list_skills(
    source: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(current_user),
) -> dict:
    stmt = select(Skill).order_by(Skill.source, Skill.external_id)
    count_stmt = select(func.count(Skill.id))
    if source:
        stmt = stmt.where(Skill.source == source)
        count_stmt = count_stmt.where(Skill.source == source)
    if q:
        stmt = stmt.where(Skill.name.ilike(f"%{q}%"))
        count_stmt = count_stmt.where(Skill.name.ilike(f"%{q}%"))
    total = (await db.execute(count_stmt)).scalar() or 0
    rows = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()
    return {
        "total": total,
        "items": [
            {"id": s.id, "source": s.source, "external_id": s.external_id, "name": s.name, "category": s.category}
            for s in rows
        ],
    }


@router.get("/{skill_id}")
async def get_skill(skill_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    skill = await db.get(Skill, skill_id)
    if not skill:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Skill não encontrada")
    return {
        "id": skill.id, "source": skill.source, "external_id": skill.external_id,
        "name": skill.name, "category": skill.category, "yaml": skill.yaml_content,
        "hydrated": skill.embedding is not None,
    }
