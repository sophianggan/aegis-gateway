from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
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
    persistence: Literal["memory", "postgres"] = "memory"
    database_pool_min_size: int = Field(default=1, ge=1, le=20)
    database_pool_max_size: int = Field(default=10, ge=1, le=100)
    jwt_secret: SecretStr = Field(default=SecretStr("development-only-secret-change-me"))
    jwt_issuer: str = "aegis.local"
    jwt_audience: str = "aegis-gateway"
    audit_hmac_key: SecretStr = Field(default=SecretStr("development-only-audit-key-change"))
    model_provider: Literal["deterministic", "openai-compatible"] = "deterministic"
    model_base_url: str = "http://localhost:11434/v1"
    model_api_key: SecretStr = Field(default=SecretStr(""))
    model_name: str = "local-model"
    request_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_query_characters: int = Field(default=8_000, ge=1, le=100_000)
    max_context_records: int = Field(default=20, ge=1, le=100)
    max_context_bytes: int = Field(default=64_000, ge=1_024, le=10_000_000)
    allowed_query_purposes: frozenset[str] = frozenset(
        {"analysis", "operations-review", "incident-response"}
    )
    rate_limit_requests_per_minute: int = Field(default=60, ge=1, le=100_000)
    rate_limit_burst: int = Field(default=10, ge=1, le=10_000)
    rate_limit_max_identities: int = Field(default=10_000, ge=100, le=1_000_000)
    metrics_enabled: bool = True

    @field_validator("allowed_query_purposes", mode="before")
    @classmethod
    def normalize_purposes(cls, value: object) -> object:
        if isinstance(value, str) and not value.lstrip().startswith("["):
            value = value.split(",")
        if isinstance(value, (list, set, frozenset, tuple)):
            return frozenset(
                str(item).strip().lower().replace(" ", "-") for item in value if str(item).strip()
            )
        return value

    @model_validator(mode="after")
    def validate_runtime_safety(self) -> Self:
        if self.database_pool_min_size > self.database_pool_max_size:
            raise ValueError("database pool minimum cannot exceed maximum")
        if not self.allowed_query_purposes:
            raise ValueError("at least one query purpose must be allowed")
        if self.environment != "production":
            return self

        violations: list[str] = []
        jwt_value = self.jwt_secret.get_secret_value()
        audit_value = self.audit_hmac_key.get_secret_value()
        if self.persistence != "postgres":
            violations.append("production persistence must use postgres")
        if self.model_provider != "openai-compatible":
            violations.append("production model provider must use an isolated endpoint")
        if len(jwt_value) < 32 or "development-only" in jwt_value:
            violations.append("production JWT secret must be independently provisioned")
        if len(audit_value) < 32 or "development-only" in audit_value:
            violations.append("production audit key must be independently provisioned")
        if jwt_value == audit_value:
            violations.append("identity and audit keys must be different")
        if "aegis:aegis@localhost" in self.database_url:
            violations.append("production database URL must be independently provisioned")
        if violations:
            raise ValueError("; ".join(violations))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
