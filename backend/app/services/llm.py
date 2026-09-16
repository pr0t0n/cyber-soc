"""Cliente de chat LLM (API compatível com OpenAI) — provider-agnóstico via env.

Padrão: Ollama local (`LLM_BASE_URL=http://ollama:11434/v1`). Sem o serviço
disponível, o chat degrada para uma resposta baseada apenas no contexto (sem
geração), nunca falha silenciosamente com uma resposta fabricada.
"""
from __future__ import annotations

import httpx

from ..config import settings


class LlmUnavailable(RuntimeError):
    pass


async def chat_completion(system_prompt: str, user_message: str) -> str:
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"} if settings.llm_api_key else {}
    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            r = await client.post(url, json=body, headers=headers)
        if r.status_code >= 400:
            raise LlmUnavailable(f"HTTP {r.status_code}")
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError) as exc:
        raise LlmUnavailable(str(exc)) from exc
