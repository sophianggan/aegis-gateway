from typing import Any


class AegisError(Exception):
    """Base error carrying a stable machine-readable code."""

    code = "aegis_error"
    status_code = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(AegisError):
    code = "authentication_failed"
    status_code = 401


class AuthorizationError(AegisError):
    code = "authorization_denied"
    status_code = 403


class PolicyViolationError(AegisError):
    code = "policy_violation"
    status_code = 422


class UpstreamModelError(AegisError):
    code = "upstream_model_error"
    status_code = 502
