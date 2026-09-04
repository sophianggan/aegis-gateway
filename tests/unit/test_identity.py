from datetime import UTC, datetime, timedelta

import jwt
import pytest
from pydantic import SecretStr

from aegis.config import Settings
from aegis.domain.models import Classification
from aegis.errors import AuthenticationError
from aegis.security.identity import TokenAuthenticator


@pytest.fixture
def authenticator() -> TokenAuthenticator:
    return TokenAuthenticator(
        Settings(
            environment="test",
            jwt_secret=SecretStr("test-jwt-secret-that-is-long-enough"),
            audit_hmac_key=SecretStr("test-audit-key-that-is-long-enough"),
        )
    )


def test_round_trips_trusted_identity_claims(authenticator: TokenAuthenticator) -> None:
    token = authenticator.issue_development_token(
        subject="casey",
        clearance=Classification.CONFIDENTIAL,
        compartments={"Operations"},
        roles={"Auditor"},
    )

    principal = authenticator.authenticate(f"Bearer {token}")

    assert principal.subject == "casey"
    assert principal.clearance == Classification.CONFIDENTIAL
    assert principal.compartments == {"operations"}
    assert principal.roles == {"auditor"}
    assert principal.token_id is not None


def test_development_tokens_receive_unique_revocation_identifiers(
    authenticator: TokenAuthenticator,
) -> None:
    first = authenticator.issue_development_token(
        subject="casey", clearance=Classification.INTERNAL
    )
    second = authenticator.issue_development_token(
        subject="casey", clearance=Classification.INTERNAL
    )

    first_principal = authenticator.authenticate(f"Bearer {first}")
    second_principal = authenticator.authenticate(f"Bearer {second}")

    assert first != second
    assert first_principal.token_id != second_principal.token_id


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer", "Token abc"])
def test_rejects_missing_or_malformed_authorization(
    authenticator: TokenAuthenticator, header: str | None
) -> None:
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(header)


def test_rejects_expired_token(authenticator: TokenAuthenticator) -> None:
    token = authenticator.issue_development_token(
        subject="casey",
        clearance=Classification.INTERNAL,
        lifetime=timedelta(seconds=-1),
    )
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(f"Bearer {token}")


def test_rejects_token_signed_by_another_key(authenticator: TokenAuthenticator) -> None:
    other = TokenAuthenticator(
        Settings(
            environment="test",
            jwt_secret=SecretStr("different-test-secret-that-is-long"),
            audit_hmac_key=SecretStr("test-audit-key-that-is-long-enough"),
        )
    )
    token = other.issue_development_token(subject="casey", clearance=Classification.INTERNAL)
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(f"Bearer {token}")


def test_rejects_oversized_identity_claim_collections(
    authenticator: TokenAuthenticator,
) -> None:
    token = authenticator.issue_development_token(
        subject="casey",
        clearance=Classification.INTERNAL,
        roles={f"role-{index}" for index in range(51)},
    )

    with pytest.raises(AuthenticationError, match="invalid or expired"):
        authenticator.authenticate(f"Bearer {token}")


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("sub", None),
        ("sub", "   "),
        ("jti", 123),
        ("roles", "auditor"),
        ("roles", ["auditor", 7]),
        ("compartments", {"operations": True}),
    ],
)
def test_rejects_malformed_identity_claim_types(
    authenticator: TokenAuthenticator, claim: str, value: object
) -> None:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": "casey",
        "clearance": "INTERNAL",
        "jti": "token-1",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "iss": "aegis.local",
        "aud": "aegis-gateway",
    }
    claims[claim] = value
    token = jwt.encode(
        claims,
        "test-jwt-secret-that-is-long-enough",
        algorithm="HS256",
    )

    with pytest.raises(AuthenticationError, match="invalid or expired"):
        authenticator.authenticate(f"Bearer {token}")


def test_disables_development_token_issuance_in_production() -> None:
    authenticator = TokenAuthenticator(
        Settings(
            environment="production",
            persistence="postgres",
            database_url="postgresql://runtime:credential@database.internal/aegis",
            jwt_secret=SecretStr("production-jwt-secret-that-is-long-enough"),
            audit_hmac_key=SecretStr("production-audit-key-that-is-long-enough"),
            model_provider="openai-compatible",
            model_base_url="https://model.internal/v1",
        )
    )

    with pytest.raises(RuntimeError, match="disabled in production"):
        authenticator.issue_development_token(
            subject="casey",
            clearance=Classification.INTERNAL,
        )
