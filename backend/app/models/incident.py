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

    # GLPI é o sistema de registro da tratativa (ticket aberto por
    # `notify.py` quando o incidente é criado/escalado) — pedido real: o
    # status aqui não deve ser uma lista suspensa editável à parte, tem que
    # refletir o que o GLPI diz de verdade (`sync_glpi_status`,
    # app/services/notify.py), senão os dois lados divergem em silêncio.
    # `None` = nenhum ticket GLPI foi aberto pra este incidente (severidade
    # fora do que o conector notifica, ou nenhum conector GLPI configurado).
    glpi_ticket_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    glpi_status_raw: Mapped[int | None] = mapped_column(Integer, nullable=True)
    glpi_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Marcos do ciclo de vida do ticket para as métricas MTTD/MTTR/MTTC/MTTR
    # (Visão Operacional) — nunca regridem depois de gravados (`sync_glpi_
    # status` só grava cada um a primeira vez que o observa, ver notify.py).
    # `takeintoaccount`/`solved`/`closed` vêm de campos nativos do próprio
    # GLPI (`takeintoaccountdate`/`solvedate`/`closedate` da API de Ticket) —
    # não são inventados aqui. `planned_at` não tem campo nativo equivalente
    # (o fluxo genérico do GLPI não separa "contenção" de "resposta") — é a
    # primeira vez que observamos o ticket em status 3 ("Processing (Planned)"),
    # usado como proxy do início da fase de bloqueio da ameaça.
    glpi_takeintoaccount_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    glpi_planned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    glpi_solved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    glpi_closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
