"""ASM (Attack Surface Management) mínimo — reaproveita o MESMO `query_shodan`
já usado reativamente em `threat_intel.py::analyze_traffic`, só que chamado
PROATIVAMENTE contra os IPs públicos que a própria organização já expôs nos
eventos recebidos (destino de tráfego observado pelo SIEM), não contra o
`src_ip` de quem está atacando. Não é ASM completo (não descobre subdomínio
novo nem certificado) — é o que dá pra fazer sem infraestrutura de varredura
nova, reaproveitando o que já existe."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Event, IocCache
from . import threat_intel

ASM_WINDOW_DAYS = 30
_INDICATOR_TYPE = "asm"


async def _list_exposed_public_ips(db: AsyncSession, *, window_days: int) -> list[str]:
    since = datetime.now(timezone.utc) - timedelta(days=window_days)
    rows = (
        await db.execute(select(Event.dst_ip).where(Event.received_at >= since, Event.dst_ip.is_not(None)).distinct())
    ).scalars().all()
    return sorted({ip for ip in rows if threat_intel.is_public_ip(ip)})


async def _cache_fresh(db: AsyncSession, ip: str) -> bool:
    row = (
        await db.execute(
            select(IocCache.checked_at).where(IocCache.indicator == ip, IocCache.indicator_type == _INDICATOR_TYPE)
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    checked = row if row.tzinfo else row.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - checked) <= timedelta(hours=settings.intel_cache_ttl_hours)


async def refresh_exposed_assets(db: AsyncSession, *, window_days: int = ASM_WINDOW_DAYS) -> int:
    """Consulta o Shodan pra cada IP público de destino observado nos últimos
    `window_days` que ainda não tem cache válido. Sem provedor Shodan
    habilitado (Administração -> Integrações), não faz nada — nunca simula
    uma resposta. Retorna quantos IPs foram efetivamente consultados (útil
    pro chamador logar)."""
    providers = await threat_intel.get_providers(db)
    shodan_key = next((c.config.get("api_key") for c in providers if c.type == "shodan"), None)
    if not shodan_key:
        return 0
    ips = await _list_exposed_public_ips(db, window_days=window_days)
    checked = 0
    for ip in ips:
        if await _cache_fresh(db, ip):
            continue
        result = await threat_intel.query_shodan(shodan_key, ip)
        row = (
            await db.execute(
                select(IocCache).where(IocCache.indicator == ip, IocCache.indicator_type == _INDICATOR_TYPE)
            )
        ).scalar_one_or_none()
        if row:
            row.result = result
            row.checked_at = datetime.now(timezone.utc)
        else:
            db.add(IocCache(indicator=ip, indicator_type=_INDICATOR_TYPE, result=result, checked_at=datetime.now(timezone.utc)))
        await db.commit()
        checked += 1
    return checked


async def list_exposed_assets(db: AsyncSession, *, window_days: int = ASM_WINDOW_DAYS) -> dict[str, Any]:
    """Shape pro dashboard: cada IP público de destino observado + o que o
    Shodan já sabe sobre ele (cache), quando houver. `shodan_configured`
    deixa explícito pro frontend o motivo de uma lista vazia (sem provedor
    configurado é bem diferente de "nenhum IP público exposto")."""
    ips = await _list_exposed_public_ips(db, window_days=window_days)
    providers = await threat_intel.get_providers(db)
    shodan_configured = any(c.type == "shodan" for c in providers)

    cached: dict[str, dict] = {}
    if ips:
        rows = (
            await db.execute(
                select(IocCache.indicator, IocCache.result, IocCache.checked_at).where(
                    IocCache.indicator.in_(ips), IocCache.indicator_type == _INDICATOR_TYPE
                )
            )
        ).all()
        cached = {ip: {"result": result, "checked_at": checked_at} for ip, result, checked_at in rows}

    items = []
    for ip in ips:
        entry = cached.get(ip)
        shodan = (entry or {}).get("result") or {}
        checked_at = (entry or {}).get("checked_at")
        items.append({
            "ip": ip,
            "checked_at": checked_at.isoformat() if checked_at else None,
            "status": shodan.get("status") or ("aguardando_consulta" if shodan_configured else "sem_provedor_configurado"),
            "found": shodan.get("found"),
            "ports": shodan.get("ports") or [],
            "org": shodan.get("org"),
            "tags": shodan.get("tags") or [],
            "vulns": shodan.get("vulns") or [],
        })
    return {"window_days": window_days, "shodan_configured": shodan_configured, "items": items}
