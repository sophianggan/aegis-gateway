import pytest

from aegis.errors import AuthorizationError
from aegis.services.purpose import PurposePolicy


def test_normalizes_human_readable_purpose_before_allowing() -> None:
    policy = PurposePolicy(frozenset({"operations-review"}))
    assert policy.enforce("  Operations   Review ") == "operations-review"


def test_rejects_unapproved_purpose_with_safe_details() -> None:
    policy = PurposePolicy(frozenset({"analysis", "incident-response"}))
    with pytest.raises(AuthorizationError) as captured:
        policy.enforce("unbounded exploration")

    assert captured.value.details == {
        "purpose": "unbounded-exploration",
        "allowed_purposes": ["analysis", "incident-response"],
    }


def test_normalizes_configured_purposes() -> None:
    policy = PurposePolicy(frozenset({"  Incident Response  "}))

    assert policy.enforce("incident response") == "incident-response"


@pytest.mark.parametrize("purposes", [frozenset(), frozenset({"   "})])
def test_rejects_missing_configured_purposes(purposes: frozenset[str]) -> None:
    with pytest.raises(ValueError, match="at least one"):
        PurposePolicy(purposes)
