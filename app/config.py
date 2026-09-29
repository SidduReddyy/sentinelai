"""
SentinelAI — Application Configuration
Loads settings from environment variables / .env file.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------
    secret_key: str = "dev-insecure-secret-change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    database_url: str = "sqlite:///./sentinelai.db"

    # ------------------------------------------------------------------
    # AI Provider
    # ------------------------------------------------------------------
    ai_provider: str = "none"   # "none" | "openai" | "anthropic"
    ai_api_key: str = ""
    ai_model: str = ""

    # ------------------------------------------------------------------
    # Initial admin (used only on first DB init)
    # ------------------------------------------------------------------
    initial_admin_username: str = "admin"
    initial_admin_password: str = "ChangeMe123!"
    initial_admin_email: str = "admin@sentinelai.local"

    # ------------------------------------------------------------------
    # Detection thresholds
    # ------------------------------------------------------------------
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    access_denied_threshold: int = 10
    access_denied_window_seconds: int = 300
    event_burst_threshold: int = 50
    event_burst_window_seconds: int = 60

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------
    backend_url: str = "http://localhost:8000"
    cors_origins: str = "http://localhost:8501"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_configured(self) -> bool:
        return self.ai_provider.lower() not in ("none", "") and bool(self.ai_api_key)


@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
