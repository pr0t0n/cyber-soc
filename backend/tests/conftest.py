"""Fixtures de teste: banco SQLite isolado, sem rede/LLM externo."""
import os
import pathlib

_TEST_DB = pathlib.Path(__file__).parent / "_test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB}"
os.environ["JWT_SECRET"] = "test-secret"
os.environ.setdefault("AUTO_GEO_ON_INGEST", "false")
# O motor de regras (Supervisor LangGraph + MCP + Ollama real) é testado à
# parte, com analyze_event() monkeypatched — sem isso, todo POST /api/ingest
# pagaria o custo de um subprocesso MCP + uma chamada de LLM real que falha.
os.environ.setdefault("RULES_ENGINE_ENABLED", "false")

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.bootstrap import bootstrap  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Connector  # noqa: E402

# A ingestão só aceita fonte com integração cadastrada+habilitada (ver
# app/api/ingest.py _authorize_source) — sem isso, todo teste que ingere um
# evento de teste precisaria criar seu próprio conector via API antes. Em vez
# de repetir isso em cada teste, o setup do banco já cadastra um conector
# "de fábrica" habilitado para cada fonte suportada, com este token
# compartilhado — testes que precisam de um conector com config específica
# (ex.: client_tag) continuam livres para criar o seu próprio, à parte.
TEST_INGEST_TOKEN = "test-ingest-token"


@pytest_asyncio.fixture(autouse=True)
async def _setup_db():
    if _TEST_DB.exists():
        _TEST_DB.unlink()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await bootstrap()
    async with SessionLocal() as db:
        for source in ("wazuh", "elastic", "generic"):
            db.add(Connector(
                name=f"Teste {source}", kind="siem", type=source, status="enabled",
                config={"token": TEST_INGEST_TOKEN},
            ))
        await db.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    if _TEST_DB.exists():
        _TEST_DB.unlink()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_headers(client):
    resp = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "admin123"})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
def ingest_headers():
    """Token do conector 'de fábrica' criado em `_setup_db` — use nos testes
    que só precisam que a ingestão funcione, sem se importar com qual
    conector especificamente autenticou a chamada."""
    return {"Authorization": f"Bearer {TEST_INGEST_TOKEN}"}
