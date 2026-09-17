from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class IocCache(Base):
    """Cache de reputação de IOC (protege a cota das APIs externas).

    Chave é (indicator, indicator_type), não só `indicator`: o mesmo IP tem uma
    entrada "geo" (app/services/geo.py) e uma "ip" (app/services/threat_intel.py)
    independentes — uma unicidade só em `indicator` fazia a busca de geo
    "vazar" como cache (vazio) de threat intel para o mesmo IP, nunca chamando
    Shodan/AbuseIPDB de verdade."""

    __tablename__ = "ioc_cache"
    __table_args__ = (UniqueConstraint("indicator", "indicator_type", name="uq_ioc_cache_indicator_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator: Mapped[str] = mapped_column(String(300), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16))
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
