"""Chat do Copilot — perguntas sobre evento/incidente/risco/ip/usuário via LLM
local, com contexto real do banco (sem RAG vetorial ainda — próxima fase)."""
from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Event, User
from ..services.llm import LlmUnavailable, chat_completion

router = APIRouter(prefix="/api/chat", tags=["chat"])

_SYSTEM_PROMPT = (
    "Você é o Copilot de um SOC/CSIRT N1/N2. Responda de forma objetiva e "
    "estritamente defensiva, citando o contexto de eventos fornecido. Se o "
    "contexto não tiver a resposta, diga que não há dado suficiente."
)


class ChatIn(BaseModel):
    message: str


async def _recent_context(db: AsyncSession, limit: int = 20) -> str:
    rows = (await db.execute(select(Event).order_by(Event.timestamp.desc()).limit(limit))).scalars().all()
    if not rows:
        return "Nenhum evento ingerido ainda."
    lines = [
        f"- #{e.id} [{e.severity}] {e.type} {e.src_ip}->{e.dst_ip}:{e.dst_port}/{e.protocol} "
        f"risco={e.risk_score} mitre={','.join(e.mitre or [])}"
        for e in rows
    ]
    return "Eventos recentes:\n" + "\n".join(lines)


@router.post("")
async def chat(body: ChatIn, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    context = await _recent_context(db)
    prompt = f"{context}\n\nPergunta do analista: {body.message}"
    try:
        answer = await chat_completion(_SYSTEM_PROMPT, prompt)
        return {"answer": answer, "degraded": False}
    except LlmUnavailable:
        return {
            "answer": (
                "IA indisponível no momento (modelo local não respondeu). "
                f"Contexto bruto para você avaliar:\n\n{context}"
            ),
            "degraded": True,
        }
