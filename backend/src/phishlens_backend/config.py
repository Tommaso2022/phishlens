"""Configurazione del backend, letta solo da variabili d'ambiente (prefisso PHISHLENS_).

I segreti non hanno valori predefiniti: se mancano, il backend non parte.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISHLENS_", extra="ignore")

    env: str = "production"
    database_url: SecretStr
    redis_url: SecretStr
    base_url: str = "http://127.0.0.1:8000"  # usato nei link delle email

    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    mail_from: str = "PhishLens <no-reply@phishlens.invalid>"

    hibp_enabled: bool = True
    verify_token_hours: int = Field(default=24, ge=1, le=72)
    register_per_ip_per_day: int = Field(default=5, ge=1)

    @property
    def is_development(self) -> bool:
        return self.env == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
