"""Geolocalização de IP de origem para o world map do dashboard.

Usa a API pública e gratuita ipinfo.io (sem token, uso limitado por IP/dia) —
cache agressivo (`IocCache`, indicator_type="geo") para proteger a cota. Sem
resposta/rede, o evento fica sem geo (não bloqueia a ingestão). ip-api.com foi
tentado primeiro e descartado: inacessível a partir desta rede (timeout tanto
em HTTP quanto HTTPS, com ou sem Docker) mesmo com egress liberado para outros
hosts — provável bloqueio anti-abuso deles para esta faixa de IP de origem.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import IocCache

_TIMEOUT = 5.0


async def _cache_get(db: AsyncSession, ip: str) -> dict | None:
    row = (
        await db.execute(select(IocCache).where(IocCache.indicator == ip, IocCache.indicator_type == "geo"))
    ).scalar_one_or_none()
    if not row:
        return None
    checked = row.checked_at
    if checked and checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    if checked and (datetime.now(timezone.utc) - checked) > timedelta(hours=settings.geo_cache_ttl_hours):
        return None
    return dict(row.result or {})


async def _cache_put(db: AsyncSession, ip: str, result: dict) -> None:
    row = (
        await db.execute(select(IocCache).where(IocCache.indicator == ip, IocCache.indicator_type == "geo"))
    ).scalar_one_or_none()
    if row:
        row.result = result
        row.checked_at = datetime.now(timezone.utc)
    else:
        db.add(IocCache(indicator=ip, indicator_type="geo", result=result, checked_at=datetime.now(timezone.utc)))
    await db.commit()


async def query_geo(ip: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"https://ipinfo.io/{ip}/json")
        if r.status_code >= 400:
            return None
        data = r.json() or {}
        loc = data.get("loc")  # "lat,lon"
        if not loc or "," not in loc:
            return None
        lat_str, lon_str = loc.split(",", 1)
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": float(lat_str),
            "lon": float(lon_str),
        }
    except (httpx.HTTPError, ValueError):
        return None


async def lookup_geo(db: AsyncSession, ip: str) -> dict | None:
    cached = await _cache_get(db, ip)
    if cached is not None:
        return cached or None
    geo = await query_geo(ip)
    await _cache_put(db, ip, geo or {})
    return geo
