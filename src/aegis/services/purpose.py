from __future__ import annotations

from aegis.errors import AuthorizationError


class PurposePolicy:
    """Normalize and enforce deployment-approved data-use purposes."""

    def __init__(self, allowed_purposes: frozenset[str]) -> None:
        if not allowed_purposes:
            raise ValueError("purpose policy requires at least one allowed purpose")
        self._allowed = allowed_purposes

    @staticmethod
    def normalize(purpose: str) -> str:
        return "-".join(purpose.strip().lower().split())

    def enforce(self, purpose: str) -> str:
        normalized = self.normalize(purpose)
        if normalized not in self._allowed:
            raise AuthorizationError(
                "query purpose is not approved for this deployment",
                details={"purpose": normalized, "allowed_purposes": sorted(self._allowed)},
            )
        return normalized
