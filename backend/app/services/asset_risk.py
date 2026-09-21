"""Registro de ativos derivado do próprio SIEM — pedido real: em vez de
depender de um CMDB externo (GLPI ou outro) que o cliente precisa manter
atualizado, cada hostname/IP observado nos eventos recebidos vira uma linha
de risco calculada do histórico REAL já processado pelo motor de regras
(confirmações de skill, diversidade de técnica MITRE, incidente aberto) —
"lixo entra, lixo sai" nunca é um risco aqui, porque não há cadastro manual
algum, só o que a plataforma já viu de verdade."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, Incident
from .mitre import technique_tactic_pt

ASSET_RISK_WINDOW_DAYS = 30
_MAX_ASSETS_RETURNED = 50

_SEVERITY_POINTS = {"critica": 10, "alta": 6, "media": 3, "baixa": 1, "info": 0}


def _is_internal_ip(value: str | None) -> bool:
    """Só IP privado/loopback/link-local conta como "nosso ativo" — um IP
    público é o ATACANTE (já coberto por AbuseIPDB/Shodan em threat_intel.py),
    nunca algo que estejamos protegendo."""
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _asset_keys_for_event(hostname: str | None, src_ip: str | None, dst_ip: str | None) -> list[tuple[str, str]]:
    """Identidade do(s) ativo(s) que este evento envolve. Hostname do agente
    Wazuh é preferido (estável mesmo com IP mudando via DHCP) e identifica UM
    ativo só — o próprio host monitorado. Sem hostname (alerta de rede sem
    contexto de agente local, ou fonte não-Wazuh), cada IP PRIVADO envolvido
    (origem e/ou destino) vira um ativo próprio — um evento interno-a-interno
    (movimento lateral) contribui risco pros dois lados, de propósito."""
    if hostname:
        return [("hostname", hostname)]
    keys = []
    for ip in (src_ip, dst_ip):
        if ip and _is_internal_ip(ip):
            keys.append(("ip", ip))
    return keys


def _severity_points(severity: str) -> int:
    return _SEVERITY_POINTS.get(severity, 0)


def _risk_score(*, confirmed_count: int, technique_count: int, has_open_incident: bool, worst_severity_points: int) -> int:
    """Aditivo e transparente (mesmo espírito de `_escalate_risk_score` em
    rules_engine.py) — nunca uma caixa-preta. Cada componente satura sozinho
    antes da soma final, pra um único fator extremo (ex.: 50 confirmações)
    não dominar o placar sozinho."""
    score = 0
    score += min(confirmed_count * 15, 60)      # confirmações reais de skill — o sinal mais forte
    score += min(technique_count * 8, 24)        # diversidade de técnica MITRE — não é sempre o mesmo alerta repetido
    score += 15 if has_open_incident else 0      # urgência: ainda não tratado
    score += worst_severity_points               # pior severidade já vista, empurrão pequeno
    return min(100, score)


async def compute_asset_risk(
    db: AsyncSession, *, tag: str | None = None, window_days: int = ASSET_RISK_WINDOW_DAYS,
) -> list[dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(days=window_days)
    stmt = select(
        Event.agent_hostname, Event.src_ip, Event.dst_ip, Event.severity,
        Event.rules_engine_status, Event.mitre, Event.incident_id, Event.received_at,
    ).where(Event.received_at >= since)
    if tag:
        stmt = stmt.where(Event.tag == tag)
    rows = (await db.execute(stmt)).all()
    if not rows:
        return []

    open_incident_ids = set(
        (await db.execute(select(Incident.id).where(Incident.status != "concluido"))).scalars().all()
    )

    assets: dict[tuple[str, str], dict[str, Any]] = {}
    for hostname, src_ip, dst_ip, severity, rules_status, mitre, incident_id, received_at in rows:
        # Categoria do ataque = mesma lógica de "Attack Vector" (dashboard.py)
        # — tática MITRE da primeira técnica do evento, ou um balde explícito
        # "Sem técnica MITRE" — nunca ID cru sem contexto pro analista.
        category = technique_tactic_pt(mitre[0]) if mitre else "Sem técnica MITRE"
        for key in _asset_keys_for_event(hostname, src_ip, dst_ip):
            a = assets.get(key)
            if a is None:
                a = assets[key] = {
                    "kind": key[0], "identifier": key[1], "hostname": None, "ips": set(),
                    "event_count": 0, "confirmed_count": 0, "techniques": set(), "attack_types": {},
                    "has_open_incident": False, "worst_severity_points": 0,
                    "first_seen_at": received_at, "last_seen_at": received_at,
                }
            a["event_count"] += 1
            if hostname:
                a["hostname"] = hostname
            if src_ip:
                a["ips"].add(src_ip)
            if dst_ip:
                a["ips"].add(dst_ip)
            if rules_status == "matched":
                a["confirmed_count"] += 1
            a["techniques"].update(mitre or [])
            a["attack_types"][category] = a["attack_types"].get(category, 0) + 1
            if incident_id is not None and incident_id in open_incident_ids:
                a["has_open_incident"] = True
            a["worst_severity_points"] = max(a["worst_severity_points"], _severity_points(severity))
            if received_at < a["first_seen_at"]:
                a["first_seen_at"] = received_at
            if received_at > a["last_seen_at"]:
                a["last_seen_at"] = received_at

    results = []
    for a in assets.values():
        score = _risk_score(
            confirmed_count=a["confirmed_count"], technique_count=len(a["techniques"]),
            has_open_incident=a["has_open_incident"], worst_severity_points=a["worst_severity_points"],
        )
        attack_types = dict(sorted(a["attack_types"].items(), key=lambda kv: kv[1], reverse=True))
        results.append({
            "kind": a["kind"],
            "identifier": a["identifier"],
            "hostname": a["hostname"],
            "ips": sorted(a["ips"]),
            "event_count": a["event_count"],
            "confirmed_count": a["confirmed_count"],
            "techniques": sorted(a["techniques"]),
            "attack_types": attack_types,
            "has_open_incident": a["has_open_incident"],
            "risk_score": score,
            "first_seen_at": a["first_seen_at"].isoformat() if a["first_seen_at"] else None,
            "last_seen_at": a["last_seen_at"].isoformat() if a["last_seen_at"] else None,
        })

    # Volume primeiro de propósito ("ativos que mais receberam informações")
    # — risco continua disponível por ativo pra ordenar/destacar no frontend,
    # mas o padrão agora responde à pergunta "onde está o TRÁFEGO", não só
    # "onde está o score mais alto" (um ativo pode ter poucos eventos, todos
    # graves, e ainda assim não ser o mais RELEVANTE em termos de volume).
    results.sort(key=lambda r: (r["event_count"], r["risk_score"]), reverse=True)
    return results[:_MAX_ASSETS_RETURNED]
