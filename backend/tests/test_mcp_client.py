"""Achado real: o SDK `mcp` (stdio_client) não herda o ambiente do processo
pai por padrão — só repassa uma lista mínima de variáveis "seguras" (PATH/
HOME/...). Sem passar `env` explicitamente, o subprocesso do servidor MCP de
skills nunca via DATABASE_URL/LLM_BASE_URL reais (settings.py cai no default
hardcoded "localhost", inexistente dentro do container) — toda busca RAG
falhava silenciosamente a cada cold start do subprocesso (erro de conexão
Postgres virava "1 candidata" de texto de erro, não uma exceção tratada como
degraded)."""
import os

from app.agents.mcp_client import _build_client


def test_stdio_subprocess_receives_full_parent_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://soc:soc@postgres:5432/cyber_soc")
    client = _build_client()
    config = client.connections["skills"]
    assert config["env"] == dict(os.environ)
    assert config["env"]["DATABASE_URL"] == "postgresql+asyncpg://soc:soc@postgres:5432/cyber_soc"
