"""search_skills_multi é o que os grupos do motor de regras chamam via MCP
(app/mcp_server.py) para consultar várias fontes de uma vez — o bug real que
isso corrige: antes, cada fonte fazia sua PRÓPRIA chamada de embedding para a
mesma query (até 4x por invocação de grupo), multiplicando a chance de
timeout do Ollama sob contenção de CPU. Agora embeda uma vez só."""
from app.db import SessionLocal
from app.services import rag


async def test_search_skills_multi_embeds_query_only_once(monkeypatch):
    embed_calls = []

    async def _fake_embed(query: str):
        embed_calls.append(query)
        return None  # força o caminho de fallback textual (sem Ollama real)

    monkeypatch.setattr(rag, "embed_text", _fake_embed)
    async with SessionLocal() as db:
        await rag.search_skills_multi(db, "brute force", ["attack", "d3fend", "agent_threats", "correlation"], limit=5)

    assert len(embed_calls) == 1, "deveria embedar a query uma única vez, não uma por fonte"


async def test_search_skills_multi_searches_every_source_and_concatenates(monkeypatch):
    async def _fake_embed(query: str):
        return None

    monkeypatch.setattr(rag, "embed_text", _fake_embed)
    calls = []
    original = rag._fallback_text_search

    async def _spy_fallback(db, query, source, limit):
        calls.append(source)
        return await original(db, query, source, limit)

    monkeypatch.setattr(rag, "_fallback_text_search", _spy_fallback)
    async with SessionLocal() as db:
        results = await rag.search_skills_multi(db, "brute", ["attack", "correlation"], limit=5)

    assert calls == ["attack", "correlation"]
    assert isinstance(results, list)
