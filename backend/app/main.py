from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .agents.mcp_client import close_skill_tools
from .api import auth, chat, connectors, dashboard, events, health, incidents, ingest, skills
from .bootstrap import bootstrap
from .config import settings
from .db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.run_sync(Base.metadata.create_all)
    await bootstrap()
    yield
    # Sessão MCP é persistente pelo processo inteiro (app/agents/mcp_client.py)
    # — sem isso, o subprocesso `python -m app.mcp_server` ficaria órfão a
    # cada restart/deploy.
    await close_skill_tools()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)
app.include_router(connectors.router)
app.include_router(skills.router)
app.include_router(chat.router)
