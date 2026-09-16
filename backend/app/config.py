from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Cyber SOC Copilot"
    environment: str = "development"
    cors_allowed_origins_raw: str = Field(default="http://localhost:5173", alias="CORS_ALLOWED_ORIGINS")

    @property
    def cors_allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins_raw.split(",") if o.strip()]

    database_url: str = "postgresql+asyncpg://soc:soc@localhost:5432/cyber_soc"

    jwt_secret: str = "troque-esta-chave-em-producao"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 720

    bootstrap_admin_name: str = "Administrador"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = "admin123"

    intel_cache_ttl_hours: int = 24
    auto_enrich_on_ingest: bool = True
    geo_cache_ttl_hours: int = 168
    auto_geo_on_ingest: bool = True

    llm_base_url: str = "http://ollama:11434/v1"
    llm_api_key: str = "ollama"
    llm_model: str = "qwen2.5:1.5b"
    llm_timeout_seconds: float = 120.0
    embed_model: str = "nomic-embed-text"

    # Motor de regras (Supervisor LangGraph + MCP + RAG) rodado em background
    # após a ingestão — nunca bloqueia a resposta do POST /api/ingest.
    rules_engine_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
