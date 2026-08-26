from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from AEGIS_* environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AEGIS_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql://aegis:aegis@localhost:5432/aegis"
    jwt_secret: SecretStr = Field(default=SecretStr("development-only-secret-change-me"))
    audit_hmac_key: SecretStr = Field(default=SecretStr("development-only-audit-key-change"))
    model_provider: Literal["deterministic", "openai-compatible"] = "deterministic"
    model_base_url: str = "http://localhost:11434/v1"
    model_api_key: SecretStr = Field(default=SecretStr(""))
    model_name: str = "local-model"
    request_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_query_characters: int = Field(default=8_000, ge=1, le=100_000)
    max_context_records: int = Field(default=20, ge=1, le=100)


@lru_cache
def get_settings() -> Settings:
    return Settings()

