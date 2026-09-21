from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

# pool_size/max_overflow > default (5+10): o motor de regras abre uma sessão
# por evento em background (`run_rules_engine_for_event`) e a mantém aberta
# durante todo o veredito rápido (fast lane), não só durante a análise de IA
# — só a análise de IA em si é limitada por `_ANALYSIS_CONCURRENCY`
# (rules_engine.py). Numa rajada de ingestão (ex.: milhares de alertas do
# Suricata/Wazuh em minutos), muitas dessas sessões curtas de fast lane
# coexistem de verdade; com o default de 15 conexões no total, uma rajada
# real esgotava o pool e derrubava a API (`QueuePool limit ... reached,
# connection timed out`), observado ao validar o pipeline sob volume.
#
# `idle_in_transaction_session_timeout`/`statement_timeout` (só Postgres —
# aiosqlite não entende `server_settings`): achado real de teste de carga
# grave — sob rajada, TODAS as 50 conexões do pool ficaram "idle in
# transaction" presas por minutos (uma `SELECT` que terminou, mas nada
# depois nunca chegou a rodar), derrubando a API inteira (health check,
# login, tudo) sem nenhum erro no log. A causa exata no código não foi
# isolada com certeza sob a concorrência real observada; isto é uma rede de
# segurança no nível do Postgres — nenhuma transação trava o pool para
# sempre de novo, seja qual for a causa (bug futuro, timeout mal tratado,
# rede lenta): o próprio Postgres aborta e libera a conexão sozinho.
_connect_args = {"server_settings": {"idle_in_transaction_session_timeout": "30000", "statement_timeout": "60000"}}
engine = create_async_engine(
    settings.database_url, pool_pre_ping=True, pool_size=20, max_overflow=30,
    connect_args=_connect_args if settings.database_url.startswith("postgresql") else {},
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with SessionLocal() as session:
        yield session


async def advisory_lock(db: AsyncSession, key: str | None) -> None:
    """Trava consultiva do Postgres, escopada à transação do `db` atual
    (libera sozinha no commit/rollback, sem tabela nova nem retry). Existe
    para o padrão "lê, decide se insere ou atualiza por uma chave única"
    (achado real de teste de carga: `Incident.code` e `LearnedPattern.
    pattern_key` — duas análises concorrentes liam "não existe ainda" para a
    MESMA chave e as duas tentavam inserir, a segunda derrubando com
    violação de unicidade) — chame antes do SELECT que decide, nunca depois.
    No-op sem `key` ou fora de Postgres (SQLite nos testes não paraleliza da
    mesma forma e não tem esta função)."""
    if not key or not settings.database_url.startswith("postgresql"):
        return
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})
