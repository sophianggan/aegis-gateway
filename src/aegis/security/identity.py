from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt

from aegis.config import Settings
from aegis.domain.models import Classification, Principal
from aegis.errors import AuthenticationError


class TokenAuthenticator:
    """Validate signed bearer tokens and map trusted claims to a principal."""

    algorithm = "HS256"

    def __init__(self, settings: Settings) -> None:
        self._secret = settings.jwt_secret.get_secret_value()
        self._issuer = settings.jwt_issuer
        self._audience = settings.jwt_audience
        self._environment = settings.environment

    def authenticate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise AuthenticationError("missing bearer token")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("authorization must use the Bearer scheme")

        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[self.algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "sub", "clearance", "jti"]},
            )
            return self._principal_from_claims(claims)
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("token is invalid or expired") from exc

    @staticmethod
    def _principal_from_claims(claims: dict[str, Any]) -> Principal:
        subject = TokenAuthenticator._required_text_claim(claims, "sub")
        token_id = TokenAuthenticator._required_text_claim(claims, "jti")
        compartments = TokenAuthenticator._string_list_claim(claims, "compartments")
        roles = TokenAuthenticator._string_list_claim(claims, "roles")
        return Principal(
            subject=subject,
            clearance=Classification.parse(claims["clearance"]),
            compartments=compartments,
            roles=roles,
            token_id=token_id,
        )

    @staticmethod
    def _required_text_claim(claims: dict[str, Any], name: str) -> str:
        value = claims[name]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _string_list_claim(claims: dict[str, Any], name: str) -> frozenset[str]:
        value = claims.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise TypeError(f"{name} must be an array of strings")
        return frozenset(value)

    def issue_development_token(
        self,
        *,
        subject: str,
        clearance: Classification,
        compartments: set[str] | None = None,
        roles: set[str] | None = None,
        lifetime: timedelta = timedelta(hours=1),
    ) -> str:
        """Issue a local token; callers must never expose this in production APIs."""

        if self._environment == "production":
            raise RuntimeError("development token issuance is disabled in production")
        now = datetime.now(UTC)
        payload = {
            "sub": subject,
            "clearance": clearance.name,
            "compartments": sorted(compartments or set()),
            "roles": sorted(roles or set()),
            "jti": f"dev-{uuid4()}",
            "iat": now,
            "exp": now + lifetime,
            "iss": self._issuer,
            "aud": self._audience,
        }
        return jwt.encode(payload, self._secret, algorithm=self.algorithm)
