from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class LearnedPattern(Base):
    """Padrão aprendido a partir de vereditos reais do motor de IA — não é um
    modelo de machine learning treinado, é o mesmo princípio das vias rápidas
    determinísticas (`skill_signature_match.py`, catálogo baixado) aplicado a
    uma regra que nasce da própria observação da plataforma: quando o
    Supervisor (LangGraph) confirma repetidamente o MESMO veredito para o
    MESMO tipo de alerta (`Event.type`, a descrição que a fonte já dá — ex.:
    "Suricata: Alert - ET SCAN Amap TCP Service Scan Detected"), a plataforma
    passa a reconhecer esse padrão sem gastar outra chamada de LLM.

    Sem isso, a plataforma reprocessava do zero, sempre em segundos a minutos
    de CPU do Ollama, um alerta que ela mesma já tinha confirmado dezenas de
    vezes antes — "100% de eficiência" sem nunca ficar mais rápida/inteligente
    com o volume real recebido."""

    __tablename__ = "learned_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pattern_key: Mapped[str] = mapped_column(String(300), unique=True, index=True)  # Event.type
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    matched_skills: Mapped[list] = mapped_column(JSON, default=list)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    confirmations: Mapped[int] = mapped_column(Integer, default=1)
    promoted: Mapped[bool] = mapped_column(default=False)
    first_confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
