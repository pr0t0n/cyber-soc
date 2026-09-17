"""Análise de tráfego (IP, porta, protocolo) e enriquecimento por threat intel real.

Sem provedor configurado, a nota de risco ainda é calculada a partir de porta/
protocolo (heurística determinística) — a reputação externa (AbuseIPDB/Shodan/
VirusTotal/SOCRadar) só entra quando um conector `kind=threatintel` habilitado
existir em Administração -> Integrações. Nunca simula uma resposta de provedor.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Connector, IocCache
from ..config import settings

_TIMEOUT = 10.0
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Portas historicamente associadas a C2/RAT/acesso remoto ou serviços que não
# deveriam estar expostos sem controle (bônus de risco independente de reputação).
_RISKY_PORTS = {
    23: "Telnet exposto", 3389: "RDP exposto", 445: "SMB exposto",
    4444: "porta clássica de C2 (Metasploit)", 1337: "porta associada a shells",
    6667: "IRC (histórico de botnets)", 8080: "proxy/admin exposto",
    9001: "Tor/relay", 5900: "VNC exposto",
}
_EXPECTED_PROTOCOL_BY_PORT = {22: "TCP", 23: "TCP", 80: "TCP", 443: "TCP", 3389: "TCP", 53: "UDP"}


def is_public_ip(value: str | None) -> bool:
    if not value or not _IP_RE.match(value):
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast)


_C2_PORTS = {1080, 1443, 3333, 4443, 4444, 4445, 5555, 6666, 6667, 7777, 8443, 8888, 9001, 9050, 50050}
_C2_TAGS = {"c2", "malware", "compromised", "botnet", "tor", "proxy", "scanner", "honeypot"}


def score_traffic(*, dst_port: str | None, protocol: str | None, abuse: dict | None, shodan: dict | None = None) -> dict:
    """Nota de risco 0-100 a partir do tráfego (porta/protocolo) + reputação externa
    quando disponível — atende "analisar IP, porta, protocolo... nota de risco"."""
    score = 0
    reasons: list[str] = []

    port = int(dst_port) if dst_port and dst_port.isdigit() else None
    if port in _RISKY_PORTS:
        score += 35
        reasons.append(f"Porta {port}: {_RISKY_PORTS[port]}.")

    expected = _EXPECTED_PROTOCOL_BY_PORT.get(port or -1)
    if expected and protocol and protocol.upper() != expected:
        score += 15
        reasons.append(f"Protocolo {protocol} incomum para a porta {port} (esperado {expected}).")

    if abuse and abuse.get("status") == "ok":
        conf = int(abuse.get("abuse_confidence_score") or 0)
        score = max(score, conf)
        if conf >= 80:
            reasons.append(f"AbuseIPDB: reputação maliciosa ({conf}/100, {abuse.get('total_reports', 0)} relatos).")
        elif conf >= 25:
            reasons.append(f"AbuseIPDB: reputação suspeita ({conf}/100).")
        if abuse.get("is_tor"):
            score = max(score, 70)
            reasons.append("Nó de saída Tor.")

    if shodan and shodan.get("status") == "ok" and shodan.get("found"):
        c2_ports = sorted(set(shodan.get("ports") or []) & _C2_PORTS)
        if c2_ports:
            score = max(score, 60)
            reasons.append(f"Shodan: portas de C2/RAT expostas {c2_ports}.")
        bad_tags = sorted(set(shodan.get("tags") or []) & _C2_TAGS)
        if bad_tags:
            score = max(score, 70)
            reasons.append(f"Shodan: tags de risco {bad_tags}.")
        if shodan.get("vulns"):
            reasons.append(f"Shodan: {len(shodan['vulns'])} CVE(s) conhecido(s) no host de origem.")

    score = min(100, score)
    level = "critico" if score >= 80 else "alto" if score >= 50 else "medio" if score >= 25 else "baixo"
    return {
        "risk_score": score,
        "level": level,
        "is_malicious": score >= 50,
        "reasons": reasons or ["Sem indicadores de risco no tráfego analisado."],
    }


async def query_abuseipdb(api_key: str, ip: str, max_age_days: int = 90) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url, headers=headers, params=params)
        if r.status_code in (401, 403):
            return {"provider": "abuseipdb", "status": "auth_error", "detail": "Chave de API inválida."}
        if r.status_code == 429:
            return {"provider": "abuseipdb", "status": "rate_limited", "detail": "Limite de requisições atingido."}
        if r.status_code >= 400:
            return {"provider": "abuseipdb", "status": "error", "detail": f"HTTP {r.status_code}"}
        data = (r.json() or {}).get("data", {})
        return {
            "provider": "abuseipdb",
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_tor": bool(data.get("isTor")),
            "usage_type": data.get("usageType"),
        }
    except httpx.HTTPError as exc:
        return {"provider": "abuseipdb", "status": "error", "detail": str(exc)[:200]}


async def query_shodan(api_key: str, ip: str) -> dict:
    url = f"https://api.shodan.io/shodan/host/{ip}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url, params={"key": api_key})
        if r.status_code == 401:
            return {"provider": "shodan", "status": "auth_error", "detail": "Chave de API inválida."}
        if r.status_code == 404:
            return {"provider": "shodan", "status": "ok", "found": False, "detail": "Host sem informação no Shodan."}
        if r.status_code == 429:
            return {"provider": "shodan", "status": "rate_limited", "detail": "Limite de requisições atingido."}
        if r.status_code >= 400:
            return {"provider": "shodan", "status": "error", "detail": f"HTTP {r.status_code}"}
        data = r.json() or {}
        return {
            "provider": "shodan",
            "status": "ok",
            "found": True,
            "ports": data.get("ports", []),
            "org": data.get("org"),
            "tags": data.get("tags", []),
            "vulns": list((data.get("vulns") or {})) if isinstance(data.get("vulns"), dict) else (data.get("vulns") or []),
        }
    except httpx.HTTPError as exc:
        return {"provider": "shodan", "status": "error", "detail": str(exc)[:200]}


async def get_providers(db: AsyncSession) -> list[Connector]:
    rows = (
        await db.execute(select(Connector).where(Connector.kind == "threatintel", Connector.status == "enabled"))
    ).scalars().all()
    return list(rows)


async def _cache_get(db: AsyncSession, indicator: str) -> dict | None:
    row = (
        await db.execute(select(IocCache).where(IocCache.indicator == indicator, IocCache.indicator_type == "ip"))
    ).scalar_one_or_none()
    if not row:
        return None
    checked = row.checked_at
    if checked and checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    if checked and (datetime.now(timezone.utc) - checked) > timedelta(hours=settings.intel_cache_ttl_hours):
        return None
    return dict(row.result or {})


async def _cache_put(db: AsyncSession, indicator: str, kind: str, result: dict) -> None:
    row = (
        await db.execute(select(IocCache).where(IocCache.indicator == indicator, IocCache.indicator_type == kind))
    ).scalar_one_or_none()
    if row:
        row.result = result
        row.checked_at = datetime.now(timezone.utc)
    else:
        db.add(IocCache(indicator=indicator, indicator_type=kind, result=result, checked_at=datetime.now(timezone.utc)))
    await db.commit()


async def analyze_traffic(db: AsyncSession, *, src_ip: str | None, dst_port: str | None, protocol: str | None) -> dict:
    """Ponto único chamado na ingestão: reputação do IP de origem (se pública e
    houver provedor configurado) + porta/protocolo -> nota de risco consolidada."""
    abuse: dict | None = None
    shodan: dict | None = None
    if src_ip and is_public_ip(src_ip):
        cached = await _cache_get(db, src_ip)
        if cached is not None:
            abuse, shodan = cached.get("abuseipdb"), cached.get("shodan")
        else:
            providers = await get_providers(db)

            def _key(t: str) -> str | None:
                c = next((c for c in providers if c.type == t), None)
                return (c.config or {}).get("api_key") if c else None

            if _key("abuseipdb"):
                abuse = await query_abuseipdb(_key("abuseipdb"), src_ip)
            if _key("shodan"):
                shodan = await query_shodan(_key("shodan"), src_ip)
            if (abuse and abuse.get("status") == "ok") or (shodan and shodan.get("status") == "ok"):
                await _cache_put(db, src_ip, "ip", {"abuseipdb": abuse, "shodan": shodan})
    assessment = score_traffic(dst_port=dst_port, protocol=protocol, abuse=abuse, shodan=shodan)
    return {"abuseipdb": abuse, "shodan": shodan, "assessment": assessment}
