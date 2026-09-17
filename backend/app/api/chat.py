"""Chat do Copilot — perguntas sobre evento/incidente/risco/ip/usuário via LLM
local, com contexto real do banco (sem RAG vetorial ainda — próxima fase).

Reconhece IP na pergunta e hidrata o contexto com o que a plataforma já sabe
sobre ele (IocCache: AbuseIPDB/Shodan reais, geo) + histórico de eventos e
vereditos do motor de regras daquele IP — sem isso, o Copilot só via a lista
plana dos últimos eventos e nunca respondia bem "o que é o IP X"."""
import re

from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Event, Incident, IocCache, User
from ..services.llm import LlmUnavailable, chat_completion

router = APIRouter(prefix="/api/chat", tags=["chat"])

_SYSTEM_PROMPT = (
    "Você é o Copilot de um SOC/CSIRT N1/N2, quase um analista de DFIR. Responda "
    "de forma objetiva e estritamente defensiva, citando o contexto fornecido "
    "(eventos, threat intel real de IP, incidentes abertos). Estruture respostas "
    "sobre um IP ou evento como um analista faria: veredito (malicioso/benigno/"
    "indeterminado), evidência que sustenta isso, e próxima ação recomendada. "
    "Se o contexto não tiver a resposta, diga que não há dado suficiente — nunca "
    "invente reputação, CVE ou técnica MITRE que não esteja no contexto."
)
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class ChatIn(BaseModel):
    message: str


async def _ip_context(db: AsyncSession, ip: str) -> str:
    cache_rows = (
        await db.execute(select(IocCache).where(IocCache.indicator == ip))
    ).scalars().all()
    lines = [f"Threat intel conhecida para {ip}:"]
    for row in cache_rows:
        lines.append(f"- [{row.indicator_type}] {row.result}")
    if not cache_rows:
        lines.append("- Nenhum dado de threat intel/geo em cache para este IP ainda.")

    events = (
        await db.execute(
            select(Event).where(Event.src_ip == ip).order_by(Event.timestamp.desc()).limit(10)
        )
    ).scalars().all()
    if events:
        lines.append(f"\nEventos com origem em {ip} (mais recentes):")
        for e in events:
            lines.append(
                f"- #{e.id} [{e.severity}] {e.type} -> {e.dst_ip}:{e.dst_port}/{e.protocol} "
                f"mitre={','.join(e.mitre or [])} motor_de_regras={e.rules_engine_status} "
                f"skills={','.join(e.matched_skills or [])} recomendação={e.recommendation or '—'}"
            )
    else:
        lines.append(f"\nNenhum evento com origem em {ip} registrado.")
    return "\n".join(lines)


async def _recent_context(db: AsyncSession, limit: int = 20) -> str:
    rows = (await db.execute(select(Event).order_by(Event.timestamp.desc()).limit(limit))).scalars().all()
    if not rows:
        return "Nenhum evento ingerido ainda."
    lines = [
        f"- #{e.id} [{e.severity}] {e.type} {e.src_ip}->{e.dst_ip}:{e.dst_port}/{e.protocol} "
        f"risco={e.risk_score} mitre={','.join(e.mitre or [])} motor_de_regras={e.rules_engine_status}"
        for e in rows
    ]
    return "Eventos recentes:\n" + "\n".join(lines)


async def _incidents_context(db: AsyncSession, limit: int = 10) -> str:
    rows = (
        await db.execute(
            select(Incident).where(Incident.status != "concluido").order_by(Incident.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    if not rows:
        return "Nenhum incidente em aberto."
    lines = [f"- {i.code} [{i.status}] {i.title} (severidade={i.severity})" for i in rows]
    return "Incidentes em aberto:\n" + "\n".join(lines)


@router.post("")
async def chat(body: ChatIn, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    ips = dict.fromkeys(_IP_RE.findall(body.message))  # dedup preservando ordem
    parts = [await _recent_context(db), await _incidents_context(db)]
    for ip in ips:
        parts.append(await _ip_context(db, ip))
    context = "\n\n".join(parts)
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
