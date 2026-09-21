"""Achado real de teste de carga: duas análises concorrentes decidindo
"criar ou atualizar" por uma chave única (Incident.code, LearnedPattern.
pattern_key) liam "ainda não existe" ao mesmo tempo e cada uma tentava
inserir — a segunda derrubava com violação de unicidade. `advisory_lock`
(app/db.py) serializa esse check-then-act por chave, sem tabela nova nem
retry. É sintaxe só de Postgres; precisa ficar de fora fora dele (SQLite nos
testes) em vez de quebrar a chamada."""
from app.db import advisory_lock
from app import db as db_module


class _FakeDb:
    def __init__(self):
        self.calls = []

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params))


async def test_advisory_lock_only_runs_on_postgres(monkeypatch):
    fake = _FakeDb()

    monkeypatch.setattr(db_module.settings, "database_url", "sqlite+aiosqlite:///x.db")
    await advisory_lock(fake, "203.0.113.44")
    assert fake.calls == []

    monkeypatch.setattr(db_module.settings, "database_url", "postgresql+asyncpg://soc:soc@postgres/db")
    await advisory_lock(fake, "203.0.113.44")
    assert len(fake.calls) == 1
    assert "pg_advisory_xact_lock" in fake.calls[0][0]
    assert fake.calls[0][1] == {"key": "203.0.113.44"}

    fake.calls.clear()
    await advisory_lock(fake, None)
    assert fake.calls == []  # sem chave, nada para travar
