from datetime import timedelta

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
