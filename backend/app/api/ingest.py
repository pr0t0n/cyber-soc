"""Ingestão agnóstica de eventos (Wazuh/Elastic/genérico) -> schema canônico.

Cada evento é hidratado na chegada: reputação do IP de origem (se houver
provedor threat intel configurado) + nota de risco por porta/protocolo
(sempre calculada, mesmo sem provedor externo).
"""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from ..config import settings
from ..db import get_db
from ..models import Connector, Event
from ..services.geo import lookup_geo
from ..services.rules_engine import run_rules_engine_for_event
from ..services.threat_intel import analyze_traffic, is_public_ip

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

_SOURCES = ("wazuh", "elastic", "generic")


async def _authorize_source(db: AsyncSession, source: str, authorization: str | None) -> Connector:
    """A plataforma só coleta logs de plataformas de fato integradas — precisa
    existir um conector SIEM habilitado para esta fonte, com o token
    apresentado batendo o configurado. Sem conector nenhum (nunca integrado)
    ou com o conector desabilitado, a ingestão é recusada; não existe mais um
    "modo aberto" para fontes sem integração cadastrada — isso era o próprio
    bug relatado (a plataforma aceitava dado de qualquer fonte, integrada ou
    não)."""
    rows = (
        await db.execute(
            select(Connector).where(Connector.kind == "siem", Connector.type == source, Connector.status == "enabled")
        )
    ).scalars().all()
    if not rows:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Nenhuma integração habilitada para '{source}' — configure-a em Administração -> Integrações antes de enviar eventos.",
        )
    by_token = {c.config.get("token"): c for c in rows if (c.config or {}).get("token")}
    presented = (authorization or "").removeprefix("Bearer ").strip()
    matched = by_token.get(presented)
    if not matched:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token de ingestão inválido ou ausente.")
    return matched


def _wazuh_severity(level: int) -> str:
    if level >= 12:
        return "critica"
    if level >= 9:
        return "alta"
    if level >= 6:
        return "media"
    if level >= 3:
        return "baixa"
    return "info"


def _wazuh_hit_count(rule: dict[str, Any], data: dict[str, Any]) -> int | None:
    """`firedtimes` é o contador nativo do Wazuh de quantas vezes essa regra já
    casou — para regras de frequência (ex.: brute force, `<frequency>8</frequency>`
    no XML da regra), é o sinal mais próximo de "quantas tentativas" que o
    Wazuh expõe nativamente no próprio alerta. `frequency` é o limiar
    configurado (quantas vezes precisa casar para disparar) quando o
    `firedtimes` não vier. Sem nenhum dos dois, não inventamos um número."""
    for value in (rule.get("firedtimes"), rule.get("frequency"), data.get("count")):
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None


def _translate_wazuh(payload: dict[str, Any]) -> dict[str, Any]:
    rule = payload.get("rule") or {}
    data = payload.get("data") or {}
    agent = payload.get("agent") or {}
    mitre = (rule.get("mitre") or {}).get("id") or []
    ts_raw = payload.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)
    level = int(rule.get("level") or 0)
    # `data` nem sempre vem de um decoder nativo do Wazuh (srcip/dstip/
    # srcport/dstport/protocol) — quando a regra casada é `decoded_as: json`
    # sobre uma fonte externa (ex.: Suricata via eve.json, ruleset padrão
    # 0475-suricata_rules.xml), `data` É o registro original da fonte, com
    # os nomes de campo DELA (src_ip/dest_ip/src_port/dest_port/proto). Sem
    # o fallback, um NIDS real conectado ao Wazuh perdia IP/porta/protocolo
    # na ingestão — o evento chegava sem nenhum dos três sinais que
    # threat_intel.py e correlation_rules.py precisam para avaliar tráfego.
    src_port = data.get("srcport") or data.get("src_port")
    dst_port = data.get("dstport") or data.get("dest_port")
    return {
        "external_id": str(payload.get("id") or ""),
        "timestamp": ts,
        "type": rule.get("description") or "Evento Wazuh",
        "severity": _wazuh_severity(level),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "dst_ip": data.get("dstip") or data.get("dest_ip") or agent.get("ip"),
        "src_port": str(src_port) if src_port else None,
        "dst_port": str(dst_port) if dst_port else None,
        "protocol": data.get("protocol") or data.get("proto"),
        "mitre": list(mitre),
        "behavior": payload.get("full_log"),
        "hit_count": _wazuh_hit_count(rule, data),
        "rule_ref": f"Wazuh regra {rule.get('id', '?')}, nível {level}: {rule.get('description', '—')}",
    }


def _translate_elastic(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("_source") or payload
    event = source.get("event") or {}
    ts_raw = source.get("@timestamp") or payload.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)
    severity_map = {"critical": "critica", "high": "alta", "medium": "media", "low": "baixa"}
    return {
        "external_id": str(source.get("_id") or payload.get("_id") or ""),
        "timestamp": ts,
        "type": event.get("action") or source.get("message") or "Evento Elastic",
        "severity": severity_map.get(str(event.get("severity") or "").lower(), "info"),
        "src_ip": (source.get("source") or {}).get("ip"),
        "dst_ip": (source.get("destination") or {}).get("ip"),
        "src_port": str((source.get("source") or {}).get("port") or "") or None,
        "dst_port": str((source.get("destination") or {}).get("port") or "") or None,
        "protocol": (source.get("network") or {}).get("protocol"),
        "mitre": (source.get("threat") or {}).get("technique", {}).get("id", []) or [],
        "behavior": source.get("message"),
        # ECS não tem um campo padrão de "número de repetições" — sem um
        # contador real informado pela regra, não inventamos um.
        "hit_count": event.get("count"),
        "rule_ref": f"Elastic — severidade da regra: {event.get('severity')}" if event.get("severity") else None,
    }


def _translate_generic(payload: dict[str, Any]) -> dict[str, Any]:
    ts_raw = payload.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)
    return {
        "external_id": str(payload.get("id") or ""),
        "timestamp": ts,
        "type": payload.get("type") or "Evento",
        "severity": payload.get("severity") or "info",
        "src_ip": payload.get("src_ip"),
        "dst_ip": payload.get("dst_ip"),
        "src_port": str(payload.get("src_port")) if payload.get("src_port") else None,
        "dst_port": str(payload.get("dst_port")) if payload.get("dst_port") else None,
        "protocol": payload.get("protocol"),
        "mitre": payload.get("mitre") or [],
        "behavior": payload.get("behavior"),
        "hit_count": payload.get("hit_count"),
        "rule_ref": payload.get("rule_ref"),
    }


_TRANSLATORS = {"wazuh": _translate_wazuh, "elastic": _translate_elastic, "generic": _translate_generic}


@router.post("/{source}", status_code=status.HTTP_201_CREATED)
async def ingest(
    source: str,
    payload: dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> dict:
    if source not in _SOURCES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Fonte não suportada: {source}")
    connector = await _authorize_source(db, source, authorization)
    canonical = _TRANSLATORS[source](payload)

    intel = await analyze_traffic(
        db, src_ip=canonical["src_ip"], dst_port=canonical["dst_port"], protocol=canonical["protocol"]
    )
    geo = None
    if settings.auto_geo_on_ingest and is_public_ip(canonical["src_ip"]):
        geo = await lookup_geo(db, canonical["src_ip"])

    event = Event(
        external_id=canonical["external_id"] or None,
        timestamp=canonical["timestamp"],
        source=source,
        type=canonical["type"],
        severity=canonical["severity"],
        src_ip=canonical["src_ip"],
        dst_ip=canonical["dst_ip"],
        src_port=canonical["src_port"],
        dst_port=canonical["dst_port"],
        protocol=canonical["protocol"],
        mitre=canonical["mitre"],
        behavior=canonical["behavior"],
        hit_count=canonical.get("hit_count"),
        rule_ref=canonical.get("rule_ref"),
        risk_score=intel["assessment"]["risk_score"],
        raw=payload,
        enrichment=intel,
        tag=(connector.config or {}).get("client_tag"),
        country=(geo or {}).get("country"),
        city=(geo or {}).get("city"),
        lat=(geo or {}).get("lat"),
        lon=(geo or {}).get("lon"),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    # Motor de regras (Supervisor LangGraph + MCP/RAG) roda em background: a
    # ingestão responde imediatamente, sem esperar pela IA. É esse resultado
    # (rules_engine_status == "matched") que abre o Incidente, não mais um
    # limiar estático de risco/severidade.
    if settings.rules_engine_enabled:
        background_tasks.add_task(run_rules_engine_for_event, event.id)

    return {"id": event.id, "risk_score": event.risk_score, "severity": event.severity}
