from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base

INCIDENT_STATUSES = ("backlog", "em_andamento", "concluido")


class Incident(Base):
    """Incidente aberto quando o motor de regras de IA (Supervisor LangGraph,
    `app/agents/graph.py`) casa o evento com uma skill real (ATT&CK/D3FEND/
    Suricata/ModSecurity) — acompanhamento da tratativa (BackLog / Em
    Andamento / Concluído)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(24), unique=True)  # ex: INC-0001
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(20), default="backlog", index=True)
    severity: Mapped[str] = mapped_column(String(12), default="media", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    tag: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
