"""Administração -> Integrações: página de configuração/edição/exclusão (cardápio)."""
import secrets

import httpx
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import require_role
from ..config import settings
from ..db import get_db
from ..models import Connector, User
from ..models.connector import CONNECTOR_KINDS
from ..services import connector_schemas
from ..services import threat_intel as ti

router = APIRouter(prefix="/api/admin/connectors", tags=["connectors"])

_HTTP_TIMEOUT = 10.0


async def _test_wazuh(config: dict) -> dict:
    """Autenticação real da API REST do Wazuh Manager (não o caminho de
    ingestão, que é push) — Basic Auth em /security/user/authenticate
    devolve um JWT quando as credenciais são válidas (documentação oficial:
    https://documentation.wazuh.com/current/user-manual/api/getting-started.html)."""
    manager_url = (config.get("manager_url") or "").rstrip("/")
    if not manager_url:
        return {
            "status": "skipped",
            "detail": "Sem 'URL da API do Manager' configurada — a ingestão continua funcionando "
                      "normalmente (é o manager que envia pra cá, push), só não há o que testar aqui.",
        }
    password = config.get("api_password")
    if not password:
        return {"status": "fail", "detail": "Informe a senha da API do Manager para testar a conexão."}
    username = config.get("api_username") or "wazuh"
    url = f"{manager_url}/security/user/authenticate?raw=true"
    try:
        # verify=False: instalações on-prem do Wazuh usam certificado
        # autoassinado por padrão (mesmo motivo do `-k` na documentação
        # oficial) — este teste é sobre validar credenciais, não a cadeia TLS.
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=False) as client:
            r = await client.post(url, auth=(username, password))
        if r.status_code == 200:
            return {"status": "ok", "detail": "Autenticado na API REST do Wazuh Manager (token JWT obtido)."}
        if r.status_code in (401, 403):
            return {"status": "fail", "detail": "Usuário/senha inválidos para a API do Wazuh Manager."}
        return {"status": "fail", "detail": f"HTTP {r.status_code} ao autenticar na API do Manager."}
    except httpx.HTTPError as exc:
        return {"status": "fail", "detail": f"Manager inacessível em '{manager_url}': {exc}"[:200]}


async def _test_elastic(config: dict) -> dict:
    """GET /_cluster/health real contra o Elasticsearch configurado —
    documentação oficial: https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-cluster-health."""
    es_url = (config.get("es_url") or "").rstrip("/")
    if not es_url:
        return {
            "status": "skipped",
            "detail": "Sem 'URL do Elasticsearch' configurada — a ingestão continua funcionando "
                      "normalmente (é push, via webhook/output), só não há o que testar aqui.",
        }
    api_key = config.get("api_key")
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=False) as client:
            r = await client.get(f"{es_url}/_cluster/health", headers=headers)
        if r.status_code == 200:
            data = r.json()
            return {
                "status": "ok",
                "detail": f"Cluster '{data.get('cluster_name', '?')}' respondeu, status={data.get('status', '?')}.",
            }
        if r.status_code in (401, 403):
            return {"status": "fail", "detail": "API Key inválida para o Elasticsearch."}
        return {"status": "fail", "detail": f"HTTP {r.status_code} ao consultar /_cluster/health."}
    except httpx.HTTPError as exc:
        return {"status": "fail", "detail": f"Elasticsearch inacessível em '{es_url}': {exc}"[:200]}

async def _test_glpi(config: dict) -> dict:
    """GET /initSession real contra o GLPI configurado — mesmo fluxo de
    duas etapas que `notify.py`/`sync_all_glpi_statuses` usam pra valer
    (não um teste separado e diferente do caminho real). Documentação
    oficial: https://github.com/glpi-project/glpi/blob/main/apirest.md."""
    base_url = (config.get("base_url") or "").rstrip("/")
    app_token, user_token = config.get("app_token"), config.get("user_token")
    if not (base_url and app_token and user_token):
        return {"status": "fail", "detail": "Informe URL do GLPI, App-Token e User-Token para testar a conexão."}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=False) as client:
            r = await client.get(
                f"{base_url}/initSession",
                headers={"Authorization": f"user_token {user_token}", "App-Token": app_token},
            )
        if r.status_code == 200 and (r.json() or {}).get("session_token"):
            return {"status": "ok", "detail": "Sessão GLPI aberta com sucesso (App-Token/User-Token válidos)."}
        if r.status_code in (401, 403):
            return {"status": "fail", "detail": "App-Token/User-Token inválidos para o GLPI."}
        return {"status": "fail", "detail": f"HTTP {r.status_code} ao abrir sessão no GLPI."}
    except httpx.HTTPError as exc:
        return {"status": "fail", "detail": f"GLPI inacessível em '{base_url}': {exc}"[:200]}


_SECRET_KEYS = ("password", "secret", "token", "api_key", "app_token", "user_token")


def _mask(config: dict) -> dict:
    out = {}
    for k, v in (config or {}).items():
        if any(s in k.lower() for s in _SECRET_KEYS) and v:
            out[k] = "••••••"
        else:
            out[k] = v
    return out


def _public(c: Connector, *, reveal_token: str | None = None) -> dict:
    """`reveal_token`: só passado pelo caminho de criação (POST), onde o token
    de ingestão real ainda pode ser mostrado em claro (mesma política de
    'mostrado uma única vez' do `ingest_token` da resposta) — em qualquer
    outra visualização (GET/list/PATCH), o formato de integração usa um
    placeholder, nunca o segredo já salvo."""
    schema = connector_schemas.get_schema(c.kind, c.type) or {}
    ingest_url = f"<URL pública desta API>/api/ingest/{c.type}" if c.kind == "siem" else None
    token_for_format = reveal_token if reveal_token is not None else "<token mostrado só na criação da integração>"
    return {
        "id": c.id, "name": c.name, "kind": c.kind, "type": c.type,
        "status": c.status, "config": _mask(c.config or {}), "last_test": c.last_test,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "schema_fields": schema.get("fields", []),
        "docs_url": schema.get("docs_url"),
        "mode": schema.get("mode"),
        "test_supported": schema.get("test_supported", False),
        "integration_format": connector_schemas.render_integration_format(
            c.kind, c.type, ingest_url=ingest_url, ingest_token=token_for_format,
        ),
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
    # Token em claro (gerado agora ou informado neste mesmo request) só nesta
    # resposta — a partir daqui toda visualização vem mascarada/placeholder.
    result = _public(c, reveal_token=config.get("token") if body.kind == "siem" else None)
    if generated_token:
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


@router.get("/schemas")
async def list_schemas(_: User = Depends(require_role("admin", "gestor"))) -> dict:
    """Alimenta o formulário de Nova Integração no frontend: campos reais por
    (kind, type), link da documentação oficial e o formato exato de
    integração — em vez do textarea de JSON livre sem orientação nenhuma."""
    return {
        f"{kind}:{type_}": {
            "fields": schema.get("fields", []),
            "docs_url": schema.get("docs_url"),
            "mode": schema.get("mode"),
            "test_supported": schema.get("test_supported", False),
            "integration_format": connector_schemas.render_integration_format(
                kind, type_, ingest_url=f"<URL pública desta API>/api/ingest/{type_}" if kind == "siem" else None,
                ingest_token="<gerado ao salvar>",
            ),
        }
        for (kind, type_), schema in connector_schemas.CONNECTOR_SCHEMAS.items()
    }


@router.post("/{connector_id}/test")
async def test_connector(connector_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(require_role("admin", "gestor"))) -> dict:
    c = await db.get(Connector, connector_id)
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conector não encontrado")
    config = c.config or {}
    if c.kind == "threatintel" and c.type in ("abuseipdb", "shodan"):
        key = config.get("api_key")
        if not key:
            res = {"status": "fail", "detail": "Informe a api_key."}
        else:
            probe = await (ti.query_abuseipdb(key, "8.8.8.8") if c.type == "abuseipdb" else ti.query_shodan(key, "8.8.8.8"))
            res = {"status": "ok", "detail": "Credencial válida."} if probe.get("status") == "ok" else {
                "status": "fail", "detail": probe.get("detail", f"Falha ao consultar {c.type}.")
            }
    elif c.kind == "siem" and c.type == "wazuh":
        res = await _test_wazuh(config)
    elif c.kind == "siem" and c.type == "elastic":
        res = await _test_elastic(config)
    elif c.kind == "notification" and c.type == "glpi":
        res = await _test_glpi(config)
    else:
        res = {"status": "skipped", "detail": f"Teste ao vivo para '{c.type}' ainda não implementado; configuração salva."}
    c.last_test = res
    await db.commit()
    return res
