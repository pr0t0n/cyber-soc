"""Dispatcher de notificação/ticket — o último passo do fluxo principal que
faltava (ver análise de mercado, seção 5): quando um incidente é criado ou
escalado, avisa por mensageria (Slack/Teams) ou abre chamado (Jira/GLPI) para
os conectores `kind=notification` configurados para aquela criticidade. Sem
isso, um incidente confirmado só existia dentro da própria UI.

Formato de cada integração, extraído da documentação oficial (não
inventado):
  - Slack: Incoming Webhook, corpo `{"text": "..."}`.
    https://api.slack.com/messaging/webhooks
  - Teams: Workflows webhook (sucessor dos Office 365 Connectors,
    retirados em maio/2026) — ainda aceita MessageCard para conteúdo não
    interativo.
    https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
  - Jira: Basic Auth (e-mail + API token) contra POST /rest/api/2/issue.
    https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/
  - GLPI: fluxo de duas etapas — GET /initSession (Authorization:
    "user_token <token>" + App-Token) devolve session_token; POST /Ticket/
    com header Session-Token cria o chamado.
    https://github.com/glpi-project/glpi/blob/main/apirest.md

Cada `severities` de um conector é a lista de criticidades que disparam
aquela integração — configurada na página Resposta (frontend), guardada em
`Connector.config.severities` (mesmo padrão de config flexível já usado para
client_tag/token)."""
from __future__ import annotations

import logging
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Connector, Incident

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0

_SEVERITY_COLOR = {"critica": "d32f2f", "alta": "f57c00", "media": "fbc02d", "baixa": "1976d2", "info": "757575"}
_SEVERITY_URGENCY = {"critica": 5, "alta": 4, "media": 3, "baixa": 2, "info": 1}


def _severities_for(connector: Connector) -> set[str]:
    return set((connector.config or {}).get("severities") or [])


def _incident_summary(incident: Incident) -> str:
    return f"[{incident.severity.upper()}] {incident.code} — {incident.title}"


def _incident_body(incident: Incident) -> str:
    return f"Risco: {incident.risk_score} · Status: {incident.status} · Tag: {incident.tag or '—'}"


async def _send_slack(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return
    text = f"*{_incident_summary(incident)}*\n{_incident_body(incident)}"
    await client.post(webhook_url, json={"text": text})


async def _send_teams(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": _SEVERITY_COLOR.get(incident.severity, "757575"),
        "summary": _incident_summary(incident),
        "title": _incident_summary(incident),
        "text": _incident_body(incident),
    }
    await client.post(webhook_url, json=card)


async def _send_jira(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident) -> None:
    base_url = (config.get("base_url") or "").rstrip("/")
    email, token = config.get("email"), config.get("api_token")
    if not (base_url and email and token):
        return
    body = {
        "fields": {
            "project": {"key": config.get("project_key") or "SOC"},
            "summary": _incident_summary(incident),
            "description": _incident_body(incident),
            "issuetype": {"name": "Task"},
        }
    }
    await client.post(f"{base_url}/rest/api/2/issue", json=body, auth=(email, token))


async def _send_glpi(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident) -> None:
    base_url = (config.get("base_url") or "").rstrip("/")
    app_token, user_token = config.get("app_token"), config.get("user_token")
    if not (base_url and app_token and user_token):
        return
    auth_resp = await client.get(
        f"{base_url}/initSession",
        headers={"Authorization": f"user_token {user_token}", "App-Token": app_token},
    )
    session_token = (auth_resp.json() or {}).get("session_token")
    if not session_token:
        return
    await client.post(
        f"{base_url}/Ticket/",
        headers={"Session-Token": session_token, "App-Token": app_token},
        json={"input": {
            "name": _incident_summary(incident),
            "content": _incident_body(incident),
            "urgency": _SEVERITY_URGENCY.get(incident.severity, 3),
        }},
    )


_SENDERS = {"slack": _send_slack, "teams": _send_teams, "jira": _send_jira, "glpi": _send_glpi}


async def dispatch_incident_notification(db: AsyncSession, incident: Incident) -> None:
    """Chamado de `rules_engine.py` quando um incidente é criado ou escalado
    (nunca a cada evento fundido — um port scan com 50 eventos correlacionados
    dispararia 50 mensagens idênticas, ver Alert Fusion). Uma integração fora
    do ar nunca derruba o motor de regras: falhas são logadas, não propagadas."""
    rows = (await db.execute(
        select(Connector).where(Connector.kind == "notification", Connector.status == "enabled")
    )).scalars().all()
    targets = [c for c in rows if incident.severity in _severities_for(c) and c.type in _SENDERS]
    if not targets:
        return
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for connector in targets:
            try:
                await _SENDERS[connector.type](client, connector.config or {}, incident)
            except Exception as exc:  # noqa: BLE001 — notificação nunca derruba o motor de regras
                logger.warning("Falha ao notificar %s (%s) para %s: %s", connector.name, connector.type, incident.code, exc)
