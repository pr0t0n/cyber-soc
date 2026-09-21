from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from .types import FlexibleVector

SKILL_SOURCES = ("attack_defend", "network_signature", "web_application")


class Skill(Base):
    """Uma skill = uma unidade de conhecimento real, unificada por técnica
    MITRE ATT&CK e organizada pelo grupo do LangGraph que a consome
    (`source`): `attack_defend` (técnica ATT&CK + contramedidas D3FEND +
    Agent Threat Rules + correlação interna), `network_signature` (técnica
    ATT&CK enriquecida com as assinaturas Suricata/Emerging Threats e regras
    Sigma reais que a evidenciam) e `web_application` (técnica ATT&CK
    enriquecida com as regras ModSecurity/OWASP CRS reais que a evidenciam).
    Suricata não roda mais como processo/serviço separado na plataforma — é
    só uma das fontes usadas para gerar estas skills (ver
    app/services/skills_catalog.py). Servida como YAML na página Regras e
    usada como base de RAG pelo motor de regras (app/agents/)."""

    __tablename__ = "skills"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    external_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(300))
    category: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    yaml_content: Mapped[str] = mapped_column(Text)
    search_text: Mapped[str] = mapped_column(Text)  # texto usado para gerar o embedding
    embedding: Mapped[list[float] | None] = mapped_column(FlexibleVector(768), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
