"""
ai/core/config.py

Centralised configuration loaded from environment variables and .env files.
All other modules import from here — never read os.environ directly.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Sentinel-API AI service configuration.

    Precedence (highest → lowest):
      1. Actual environment variables
      2. .env file in the working directory
      3. Field defaults below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -----------------------------------------------------------------------
    # Service identity
    # -----------------------------------------------------------------------
    service_name: str = "sentinel-ai"
    version: str = "2.4.1"
    environment: Literal["development", "staging", "production"] = "production"

    # -----------------------------------------------------------------------
    # Network
    # -----------------------------------------------------------------------
    host: str = "0.0.0.0"
    http_port: int = 8000
    grpc_port: int = 50051
    workers: int = 1          # Keep at 1 — LLM is not safe to share across processes

    # -----------------------------------------------------------------------
    # LLM model
    # -----------------------------------------------------------------------
    model_path: Path = Path("/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf")
    model_context_length: int = 4096   # Context window in tokens
    model_max_tokens: int = 1024       # Max tokens per completion
    model_temperature: float = 0.1     # Low temp → deterministic remediation code
    model_top_p: float = 0.9
    model_n_gpu_layers: int = 0        # Set to -1 to offload all layers to GPU
    model_n_threads: int = 8           # CPU thread count for inference
    model_verbose: bool = False        # Suppress llama.cpp progress noise

    # -----------------------------------------------------------------------
    # DuckDB
    # -----------------------------------------------------------------------
    db_path: Path = Path("/data/sentinel.db")
    db_history_max_rows: int = 10_000  # Cap on scan_history table size

    # -----------------------------------------------------------------------
    # gRPC
    # -----------------------------------------------------------------------
    grpc_max_workers: int = 10
    grpc_max_message_mb: int = 64      # Max gRPC message size (MB)
    grpc_keepalive_s: int = 30

    # -----------------------------------------------------------------------
    # Security
    # -----------------------------------------------------------------------
    api_key: str = ""                  # Optional. If set, all HTTP endpoints require
                                       # X-API-Key: <key> header.
    cors_origins: list[str] = ["*"]    # Tighten in production

    # -----------------------------------------------------------------------
    # Inference behaviour
    # -----------------------------------------------------------------------
    llm_retry_attempts: int = 3
    llm_retry_wait_s: float = 2.0
    llm_fallback_enabled: bool = True  # Return template remediation if LLM fails

    # -----------------------------------------------------------------------
    # Observability
    # -----------------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    metrics_enabled: bool = True

    # -----------------------------------------------------------------------
    # Validators
    # -----------------------------------------------------------------------
    @field_validator("model_path", mode="before")
    @classmethod
    def model_path_from_env(cls, v: str | Path) -> Path:
        """Accept either a string (from env) or a Path object."""
        return Path(v)

    @model_validator(mode="after")
    def warn_if_model_missing(self) -> "Settings":
        if not self.model_path.exists():
            import warnings
            warnings.warn(
                f"LLM model not found at {self.model_path}. "
                "The AI service will start but inference will fail until the model is downloaded. "
                "Run: make download-model  or see docs/model-setup.md",
                stacklevel=2,
            )
        return self

    @field_validator("model_temperature")
    @classmethod
    def clamp_temperature(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
