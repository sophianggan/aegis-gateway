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
