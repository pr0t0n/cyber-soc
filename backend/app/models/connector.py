from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base

CONNECTOR_KINDS = ("siem", "threatintel", "notification")
SIEM_TYPES = ("wazuh", "elastic", "generic")
THREATINTEL_TYPES = ("abuseipdb", "shodan", "virustotal", "socradar")
NOTIFICATION_TYPES = ("jira", "glpi", "slack", "teams", "webhook", "email")


class Connector(Base):
    """Integração configurável (SIEM, threat intel, ITSM/comunicação) — a página
    de configuração/edição/exclusão de integrações ('cardápio') roda sobre isto."""

    __tablename__ = "connectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(16), index=True)
    type: Mapped[str] = mapped_column(String(40))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="enabled")
    last_test: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
