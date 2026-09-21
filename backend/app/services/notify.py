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
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import SessionLocal
from ..models import Connector, Event, Incident, Skill
from .baseline import weekly_activity
from .mitre import describe_technique

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0

_SEVERITY_COLOR = {"critica": "d32f2f", "alta": "f57c00", "media": "fbc02d", "baixa": "1976d2", "info": "757575"}
_SEVERITY_URGENCY = {"critica": 5, "alta": 4, "media": 3, "baixa": 2, "info": 1}

# Constantes de status do próprio GLPI (`Ticket::INCOMING`/`ASSIGNED`/
# `PLANNED`/`WAITING`/`SOLVED`/`CLOSED`, apirest.md) — pedido real: o status
# do incidente na plataforma não pode ser uma lista suspensa editável à
# parte do GLPI, tem que refletir o que o ticket diz de verdade lá.
_GLPI_STATUS_TO_INCIDENT_STATUS = {
    1: "backlog",       # Incoming (novo, ninguém pegou ainda)
    2: "em_andamento",  # Assigned
    3: "em_andamento",  # Planned
    4: "em_andamento",  # Waiting/Pending — ainda aberto, só esperando algo
    5: "concluido",     # Solved
    6: "concluido",     # Closed
}


def _severities_for(connector: Connector) -> set[str]:
    return set((connector.config or {}).get("severities") or [])


def _incident_summary(incident: Incident) -> str:
    return f"[{incident.severity.upper()}] {incident.code} — {incident.title}"


async def _describe_skills(db: AsyncSession, skill_ids: list[str]) -> list[str]:
    """"CSOC-002" -> "CSOC-002 (Varredura de portas de IP com reputação
    maliciosa confirmada)" — nome real da skill (catálogo unificado, tabela
    `skills`, skills_catalog.py) em vez do ID cru sem contexto nenhum. Um
    `external_id` pode existir em mais de uma linha (attack_defend/
    network_signature/web_application) com o mesmo nome — pega qualquer
    uma."""
    if not skill_ids:
        return []
    rows = (await db.execute(select(Skill.external_id, Skill.name).where(Skill.external_id.in_(skill_ids)))).all()
    name_by_id = dict(rows)
    return [f"{sid} ({name_by_id[sid]})" if sid in name_by_id else sid for sid in skill_ids]


async def _build_incident_body(db: AsyncSession, incident: Incident, event: Event | None) -> str:
    """Corpo do ticket/mensagem — para um analista N1 decidir sem precisar
    abrir a plataforma primeiro: de onde veio (com geo, quando disponível),
    o que a técnica MITRE significa de verdade (não só o ID), o porquê do
    alerta, o que já foi confirmado, como esta origem se compara ao próprio
    histórico de 7 dias, e o que fazer. Antes só tinha risco/status/tag —
    achado real (pedido explícito): "informação vaga" não é uma tratativa de
    nível 1 de verdade."""
    lines = [f"Risco: {incident.risk_score} · Status: {incident.status} · Tag: {incident.tag or '—'}"]
    if event is None:
        return lines[0]

    if event.src_ip or event.dst_ip:
        origin = f"{event.src_ip}:{event.src_port}" if event.src_ip and event.src_port else (event.src_ip or "—")
        dest = f"{event.dst_ip}:{event.dst_port}" if event.dst_ip and event.dst_port else (event.dst_ip or "—")
        lines.append(f"Origem: {origin} → Destino: {dest} ({event.protocol or 'protocolo desconhecido'})")

    if event.country or event.city:
        geo = ", ".join(p for p in (event.city, event.country) if p)
        lines.append(f"Geolocalização da origem: {geo}")

    if event.rules_engine_verdict and event.rules_engine_verdict.get("summary"):
        lines.append(f"Por que este alerta: {event.rules_engine_verdict['summary']}")

    if event.mitre:
        for technique_id in event.mitre:
            lines.append(f"TTP MITRE ATT&CK: {describe_technique(technique_id)}")

    # Achado real: mostrava o ID cru sem dizer o que é (ex.: "T1110, T1110")
    # — duplicado quando a mesma técnica casa exata em mais de um grupo
    # (catálogo unificado por técnica, skills_catalog.py; a duplicata em si
    # já é filtrada na origem, graph.py::supervisor_node) e sem nenhuma
    # explicação além do ID. IDs de técnica MITRE já aparecem descritos
    # acima (TTP MITRE ATT&CK) — mostra aqui só o que NÃO é uma técnica já
    # descrita (ex.: regra de correlação CSOC-00x), com o nome real da skill
    # (catálogo unificado, tabela `skills`) em vez do ID cru.
    extra_skills = [s for s in event.matched_skills if s not in (event.mitre or [])]
    if extra_skills:
        described = await _describe_skills(db, extra_skills)
        lines.append(f"Assinatura(s)/skill(s) confirmada(s): {', '.join(described)}")

    abuseipdb = (event.enrichment or {}).get("abuseipdb")
    if abuseipdb and abuseipdb.get("status") == "ok":
        lines.append(
            f"AbuseIPDB: confiança de abuso {abuseipdb.get('abuse_confidence_score', 0)}/100, "
            f"{abuseipdb.get('total_reports', 0)} denúncia(s), ISP {abuseipdb.get('isp') or 'desconhecido'}"
            f"{', nó de saída Tor' if abuseipdb.get('is_tor') else ''}."
        )
    elif abuseipdb and abuseipdb.get("status") != "ok":
        lines.append(f"AbuseIPDB: consulta não disponível ({abuseipdb.get('detail') or abuseipdb.get('status')}).")

    shodan = (event.enrichment or {}).get("shodan")
    if shodan and shodan.get("status") == "ok" and shodan.get("found"):
        ports = ", ".join(str(p) for p in (shodan.get("ports") or [])) or "nenhuma"
        vulns = ", ".join(shodan.get("vulns") or []) or "nenhuma conhecida"
        lines.append(
            f"Shodan: porta(s) exposta(s) {ports}; organização {shodan.get('org') or 'desconhecida'}; "
            f"vulnerabilidade(s) conhecida(s): {vulns}."
        )
    elif shodan and shodan.get("status") == "ok" and not shodan.get("found"):
        lines.append("Shodan: nenhuma informação encontrada para este host.")
    elif shodan and shodan.get("status") != "ok":
        lines.append(f"Shodan: consulta não disponível ({shodan.get('detail') or shodan.get('status')}).")

    assessment_reasons = ((event.enrichment or {}).get("assessment") or {}).get("reasons") or []
    if assessment_reasons:
        lines.append(f"Avaliação de risco do tráfego: {' '.join(assessment_reasons)}")

    if event.hit_count:
        lines.append(f"Ocorrências relatadas pela fonte: {event.hit_count}")
    if event.correlated_count:
        lines.append(f"Eventos correlacionados desta origem (últimos 10 min): {event.correlated_count}")

    if event.src_ip:
        weekly = await weekly_activity(db, event.src_ip, before=event.received_at)
        if weekly["first_seen_this_window"]:
            lines.append("Histórico de 7 dias: origem NUNCA vista antes desta ocorrência.")
        else:
            lines.append(
                f"Histórico de 7 dias: {weekly['total_7d']} evento(s) em {weekly['days_seen']} dia(s) distinto(s) "
                f"({', '.join(weekly['distinct_types']) or 'tipos diversos'})."
            )

    if event.recommendation:
        lines.append(f"Recomendação: {event.recommendation}")

    return "\n".join(lines)


async def _send_slack(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident, body: str) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return
    text = f"*{_incident_summary(incident)}*\n{body}"
    await client.post(webhook_url, json={"text": text})


async def _send_teams(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident, body: str) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": _SEVERITY_COLOR.get(incident.severity, "757575"),
        "summary": _incident_summary(incident),
        "title": _incident_summary(incident),
        "text": body,
    }
    await client.post(webhook_url, json=card)


async def _send_jira(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident, body: str) -> None:
    base_url = (config.get("base_url") or "").rstrip("/")
    email, token = config.get("email"), config.get("api_token")
    if not (base_url and email and token):
        return
    payload = {
        "fields": {
            "project": {"key": config.get("project_key") or "SOC"},
            "summary": _incident_summary(incident),
            "description": body,
            "issuetype": {"name": "Task"},
        }
    }
    await client.post(f"{base_url}/rest/api/2/issue", json=payload, auth=(email, token))


async def _send_glpi(client: httpx.AsyncClient, config: dict[str, Any], incident: Incident, body: str) -> int | None:
    """Retorna o id do ticket criado — pedido real: o status do incidente na
    plataforma não pode ser uma lista suspensa independente, tem que
    refletir o que o GLPI diz (`sync_glpi_status` abaixo), e pra isso
    precisamos saber QUAL ticket rastrear."""
    base_url = (config.get("base_url") or "").rstrip("/")
    app_token, user_token = config.get("app_token"), config.get("user_token")
    if not (base_url and app_token and user_token):
        return None
    auth_resp = await client.get(
        f"{base_url}/initSession",
        headers={"Authorization": f"user_token {user_token}", "App-Token": app_token},
    )
    session_token = (auth_resp.json() or {}).get("session_token")
    if not session_token:
        return None
    resp = await client.post(
        f"{base_url}/Ticket/",
        headers={"Session-Token": session_token, "App-Token": app_token},
        json={"input": {
            "name": _incident_summary(incident),
            "content": body,
            "urgency": _SEVERITY_URGENCY.get(incident.severity, 3),
        }},
    )
    return (resp.json() or {}).get("id")


_SENDERS = {"slack": _send_slack, "teams": _send_teams, "jira": _send_jira, "glpi": _send_glpi}


async def dispatch_incident_notification(incident_id: int) -> None:
    """Chamado de `rules_engine.py` quando um incidente é criado ou escalado
    (nunca a cada evento fundido — um port scan com 50 eventos correlacionados
    dispararia 50 mensagens idênticas, ver Alert Fusion). Uma integração fora
    do ar nunca derruba o motor de regras: falhas são logadas, não propagadas.

    Recebe só o ID (não a `Incident` nem a sessão do chamador) de propósito —
    achado real de teste de carga grave: a versão anterior recebia a
    `AsyncSession` do motor de regras e fazia até 4 chamadas HTTP externas
    sequenciais (GLPI/Slack/Teams/Jira, até 10s cada) SEGURANDO essa mesma
    conexão/transação aberta o tempo todo. Numa rajada com várias dezenas de
    incidentes criados quase ao mesmo tempo, isso esgotava as 50 conexões do
    pool (`app/db.py`) — cada uma presa em "idle in transaction" esperando uma
    integração externa responder, não o Postgres. Consultas de banco (targets,
    evento, corpo da mensagem) rodam numa sessão própria e curta que fecha
    ANTES de qualquer chamada de rede; o ID do ticket GLPI, se houver, é
    gravado depois numa segunda sessão própria, igualmente curta."""
    async with SessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            return
        rows = (await db.execute(
            select(Connector).where(Connector.kind == "notification", Connector.status == "enabled")
        )).scalars().all()
        targets = [c for c in rows if incident.severity in _severities_for(c) and c.type in _SENDERS]
        if not targets:
            return
        event = await db.get(Event, incident.event_id) if incident.event_id is not None else None
        body = await _build_incident_body(db, incident, event)

    glpi_ticket_id: int | None = None
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for connector in targets:
            try:
                if connector.type == "glpi":
                    ticket_id = await _send_glpi(client, connector.config or {}, incident, body)
                    if ticket_id is not None:
                        glpi_ticket_id = ticket_id
                    continue
                await _SENDERS[connector.type](client, connector.config or {}, incident, body)
            except Exception as exc:  # noqa: BLE001 — notificação nunca derruba o motor de regras
                logger.warning("Falha ao notificar %s (%s) para %s: %s", connector.name, connector.type, incident.code, exc)

    if glpi_ticket_id is not None:
        async with SessionLocal() as db:
            incident = await db.get(Incident, incident_id)
            if incident is not None:
                incident.glpi_ticket_id = glpi_ticket_id
                await db.commit()


def _parse_glpi_datetime(value: Any) -> datetime | None:
    """GLPI devolve datas como string "YYYY-MM-DD HH:MM:SS" sem fuso — mesma
    convenção já usada pelo resto da plataforma pra datas sem fuso (naive ==
    UTC, ver `received_at.tzinfo` em dashboard.py)."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def sync_all_glpi_statuses(db: AsyncSession) -> dict[str, int]:
    """Consulta o status REAL de cada ticket GLPI aberto e atualiza o
    incidente correspondente — uma sessão GLPI só, reaproveitada pra todos
    os tickets (não uma por incidente). Chamado sob demanda (endpoint
    `POST /api/incidents/sync-glpi`) e também no polling normal do
    dashboard — nunca levanta exceção pro chamador: GLPI fora do ar não pode
    derrubar a página."""
    connector = (await db.execute(
        select(Connector).where(Connector.kind == "notification", Connector.type == "glpi", Connector.status == "enabled")
    )).scalars().first()
    if connector is None:
        return {"synced": 0, "failed": 0}

    config = connector.config or {}
    base_url = (config.get("base_url") or "").rstrip("/")
    app_token, user_token = config.get("app_token"), config.get("user_token")
    if not (base_url and app_token and user_token):
        return {"synced": 0, "failed": 0}

    pending = (await db.execute(
        select(Incident).where(Incident.glpi_ticket_id.is_not(None), Incident.status != "concluido")
    )).scalars().all()
    if not pending:
        return {"synced": 0, "failed": 0}

    synced = failed = 0
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            auth_resp = await client.get(
                f"{base_url}/initSession",
                headers={"Authorization": f"user_token {user_token}", "App-Token": app_token},
            )
            session_token = (auth_resp.json() or {}).get("session_token")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Falha ao autenticar no GLPI para sincronizar status: %s", exc)
            return {"synced": 0, "failed": len(pending)}
        if not session_token:
            return {"synced": 0, "failed": len(pending)}

        for incident in pending:
            try:
                resp = await client.get(
                    f"{base_url}/Ticket/{incident.glpi_ticket_id}",
                    headers={"Session-Token": session_token, "App-Token": app_token},
                )
                if resp.status_code != 200:
                    failed += 1
                    continue
                data = resp.json() or {}
                glpi_status = data.get("status")
                incident.glpi_status_raw = glpi_status
                incident.glpi_synced_at = datetime.now(timezone.utc)
                mapped = _GLPI_STATUS_TO_INCIDENT_STATUS.get(glpi_status)
                if mapped:
                    incident.status = mapped
                # Marcos do ciclo de vida para MTTD/MTTR/MTTC/MTTR (Visão
                # Operacional) — gravados só na primeira vez que observados,
                # nunca sobrescritos depois (uma sincronização atrasada não
                # pode regredir um marco já registrado). `takeintoaccountdate`/
                # `solvedate`/`closedate` são campos nativos do próprio GLPI;
                # `glpi_planned_at` não tem equivalente nativo (o fluxo
                # genérico do GLPI não separa "contenção" de "resposta") — é
                # a primeira vez que observamos o ticket em status 3
                # ("Processing (Planned)"), usado como proxy do início do
                # bloqueio da ameaça.
                if incident.glpi_takeintoaccount_at is None:
                    incident.glpi_takeintoaccount_at = _parse_glpi_datetime(data.get("takeintoaccountdate"))
                if incident.glpi_planned_at is None and glpi_status == 3:
                    incident.glpi_planned_at = datetime.now(timezone.utc)
                if incident.glpi_solved_at is None:
                    incident.glpi_solved_at = _parse_glpi_datetime(data.get("solvedate"))
                if incident.glpi_closed_at is None:
                    incident.glpi_closed_at = _parse_glpi_datetime(data.get("closedate"))
                await db.commit()
                synced += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("Falha ao sincronizar status do ticket GLPI %s (incidente %s): %s", incident.glpi_ticket_id, incident.code, exc)
                failed += 1

    return {"synced": synced, "failed": failed}
