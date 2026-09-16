"""Administração -> Integrações: página de configuração/edição/exclusão (cardápio)."""
import secrets

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import require_role
from ..db import get_db
from ..models import Connector, User
from ..models.connector import CONNECTOR_KINDS
from ..services import threat_intel as ti

router = APIRouter(prefix="/api/admin/connectors", tags=["connectors"])

_SECRET_KEYS = ("password", "secret", "token", "api_key", "app_token", "user_token")


def _mask(config: dict) -> dict:
    out = {}
    for k, v in (config or {}).items():
        if any(s in k.lower() for s in _SECRET_KEYS) and v:
            out[k] = "••••••"
        else:
            out[k] = v
    return out


def _public(c: Connector) -> dict:
    return {
        "id": c.id, "name": c.name, "kind": c.kind, "type": c.type,
        "status": c.status, "config": _mask(c.config or {}), "last_test": c.last_test,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


class ConnectorIn(BaseModel):
    name: str
    kind: str
    type: str
    config: dict = {}
    status: str = "enabled"


class ConnectorUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    status: str | None = None


@router.get("")
async def list_connectors(db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin", "gestor"))) -> list[dict]:
    rows = (await db.execute(select(Connector).order_by(Connector.id))).scalars().all()
    return [_public(c) for c in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_connector(body: ConnectorIn, db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin", "gestor"))) -> dict:
    if body.kind not in CONNECTOR_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind inválido: {body.kind}")
    config = dict(body.config)
    generated_token = None
    if body.kind == "siem" and not config.get("token"):
        generated_token = secrets.token_urlsafe(24)
        config["token"] = generated_token
    c = Connector(name=body.name, kind=body.kind, type=body.type, config=config, status=body.status)
    db.add(c)
    await db.commit()
    await db.refresh(c)
    result = _public(c)
    if generated_token:
        # Devolvido em claro apenas nesta resposta — a partir daqui vem mascarado.
        result["ingest_token"] = generated_token
        result["ingest_endpoint"] = f"/api/ingest/{c.type}"
    return result


@router.patch("/{connector_id}")
async def update_connector(connector_id: int, body: ConnectorUpdate, db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin", "gestor"))) -> dict:
    c = await db.get(Connector, connector_id)
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conector não encontrado")
    if body.name is not None:
        c.name = body.name
    if body.status is not None:
        c.status = body.status
    if body.config is not None:
        c.config = {**(c.config or {}), **{k: v for k, v in body.config.items() if v != "••••••"}}
    await db.commit()
    await db.refresh(c)
    return _public(c)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(connector_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin"))) -> None:
    c = await db.get(Connector, connector_id)
    if c:
        await db.delete(c)
        await db.commit()


@router.post("/{connector_id}/test")
async def test_connector(connector_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin", "gestor"))) -> dict:
    c = await db.get(Connector, connector_id)
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conector não encontrado")
    if c.kind == "threatintel" and c.type in ("abuseipdb", "shodan"):
        key = (c.config or {}).get("api_key")
        if not key:
            res = {"status": "fail", "detail": "Informe a api_key."}
        else:
            probe = await (ti.query_abuseipdb(key, "8.8.8.8") if c.type == "abuseipdb" else ti.query_shodan(key, "8.8.8.8"))
            res = {"status": "ok", "detail": "Credencial válida."} if probe.get("status") == "ok" else {
                "status": "fail", "detail": probe.get("detail", f"Falha ao consultar {c.type}.")
            }
    else:
        res = {"status": "skipped", "detail": f"Teste ao vivo para '{c.type}' ainda não implementado; configuração salva."}
    c.last_test = res
    await db.commit()
    return res
