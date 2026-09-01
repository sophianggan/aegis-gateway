import pytest
from pydantic import SecretStr, ValidationError

from aegis.config import Settings


def production_settings(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "environment": "production",
        "persistence": "postgres",
        "database_url": "postgresql://runtime:credential@database.internal/aegis",
        "jwt_secret": SecretStr("independent-jwt-signing-material-0001"),
        "audit_hmac_key": SecretStr("independent-audit-signing-material-02"),
        "model_provider": "openai-compatible",
        "model_base_url": "https://model.internal/v1",
    }
    values.update(overrides)
    return values


def test_accepts_independently_provisioned_production_settings() -> None:
    settings = Settings(**production_settings())  # type: ignore[arg-type]
    assert settings.environment == "production"
    assert settings.persistence == "postgres"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"persistence": "memory"}, "persistence must use postgres"),
        ({"model_provider": "deterministic"}, "isolated endpoint"),
        ({"jwt_secret": SecretStr("short")}, "JWT secret"),
        ({"audit_hmac_key": SecretStr("short")}, "audit key"),
        (
            {
                "jwt_secret": SecretStr("same-key-material-that-is-long-enough"),
                "audit_hmac_key": SecretStr("same-key-material-that-is-long-enough"),
            },
            "must be different",
        ),
        (
            {"database_url": "postgresql://aegis:aegis@localhost:5432/aegis"},
            "database URL",
        ),
        ({"model_base_url": "http://model.internal/v1"}, "model URL must use HTTPS"),
        (
            {"model_base_url": "https://user:secret@model.internal/v1"},
            "without embedded credentials",
        ),
    ],
)
def test_rejects_unsafe_production_configuration(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(**production_settings(**override))  # type: ignore[arg-type]


def test_rejects_inverted_database_pool_bounds() -> None:
    with pytest.raises(ValidationError, match="minimum cannot exceed maximum"):
        Settings(database_pool_min_size=8, database_pool_max_size=4)


def test_development_keeps_zero_infrastructure_defaults() -> None:
    settings = Settings()
    assert settings.environment == "development"
    assert settings.persistence == "memory"


def test_normalizes_comma_separated_query_purposes() -> None:
    settings = Settings(allowed_query_purposes="Analysis, Incident Response")  # type: ignore[arg-type]
    assert settings.allowed_query_purposes == {"analysis", "incident-response"}


def test_rejects_empty_query_purpose_policy() -> None:
    with pytest.raises(ValidationError, match="at least one query purpose"):
        Settings(allowed_query_purposes=[])
