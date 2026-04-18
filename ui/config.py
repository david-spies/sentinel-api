"""ui/config.py — UI server configuration."""
from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    service_name: str = "sentinel-ui"
    version: str = "2.4.1"
    host: str = "0.0.0.0"
    port: int = 3000
    debug: bool = False

    # AI backend (FastAPI HTTP)
    ai_backend_url: str = "http://localhost:8000"
    # Optional API key forwarded to AI backend
    ai_api_key: str = ""

    # Request timeout for proxied AI calls (seconds)
    ai_timeout: float = 120.0


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
