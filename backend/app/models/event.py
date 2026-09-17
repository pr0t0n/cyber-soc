from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base

SEVERITIES = ("critica", "alta", "media", "baixa", "info")


class Event(Base):
    """Evento de segurança normalizado, agnóstico de fonte (Wazuh/Elastic/genérico)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    source: Mapped[str] = mapped_column(String(40), index=True)  # wazuh | elastic | generic
    type: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(12), index=True)

    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    src_port: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dst_port: Mapped[str | None] = mapped_column(String(32), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)

    mitre: Mapped[list] = mapped_column(JSON, default=list)  # ex: ["T1110"]
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)  # 0-100
    behavior: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Contagem de repetição/tentativas relatada pela fonte (ex.: Wazuh
    # rule.firedtimes numa regra de frequência) — sem isso, uma alegação de
    # "brute force"/scan não tem como ser sustentada com evidência quantitativa.
    hit_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Identificação da regra de origem que gerou a severidade (ex.: "Wazuh
    # rule 5720, nível 12: SSHD brute force") — a severidade é um julgamento da
    # FONTE, não do Cyber SOC; guardamos a referência para poder mostrar isso
    # explicitamente em vez de uma cor/rótulo sem explicação.
    rule_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)

    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)  # new|triaging|closed

    # Tag do conector SIEM que originou o evento (ex: "VALID") — permite filtrar
    # o dashboard por cliente/tenant específico.
    tag: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)

    # Geolocalização do IP de origem (para o world map do dashboard).
    country: Mapped[str | None] = mapped_column(String(80), nullable=True)
    city: Mapped[str | None] = mapped_column(String(120), nullable=True)
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Veredito do motor de regras de IA (Supervisor LangGraph + RAG sobre as
    # skills ATT&CK/D3FEND/Suricata/ModSecurity) — ver app/agents/graph.py.
    # `rules_engine_status`: pending -> matched|no_match. O funil do dashboard
    # usa `matched` como o estágio intermediário (não mais um limiar de risco).
    matched_skills: Mapped[list] = mapped_column(JSON, default=list)
    rules_engine_status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    rules_engine_verdict: Mapped[dict] = mapped_column(JSON, default=dict)
    # Recomendação acionável do Supervisor para o analista N1 (próximo passo,
    # citando a skill/contramedida casada) — "hidratação + recomendação" pedidas.
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
