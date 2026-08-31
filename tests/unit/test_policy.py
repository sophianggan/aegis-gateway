from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegis.domain.models import (
    Classification,
    DataField,
    Decision,
    PolicyPreviewRequest,
    Principal,
    Record,
)
from aegis.services.policy import PolicyEngine


def principal(
    clearance: Classification = Classification.INTERNAL,
    compartments: set[str] | None = None,
) -> Principal:
    return Principal(
        subject="analyst",
        clearance=clearance,
        compartments=compartments or set(),
    )


def record(**fields: DataField) -> Record:
    return Record(id=uuid4(), source="test", fields=fields)


def test_allows_fields_at_or_below_clearance() -> None:
    item = record(
        public=DataField(value="one", classification=Classification.PUBLIC),
        internal=DataField(value="two", classification=Classification.INTERNAL),
    )

    result = PolicyEngine().evaluate_record(principal(), item)

    assert result.decision.decision == Decision.ALLOW
    assert result.decision.allowed_fields == {"public": "one", "internal": "two"}


def test_filters_fields_above_clearance() -> None:
    item = record(
        visible=DataField(value="safe", classification=Classification.INTERNAL),
        hidden=DataField(value="secret", classification=Classification.RESTRICTED),
    )

    result = PolicyEngine().evaluate_record(principal(), item)

    assert result.decision.decision == Decision.FILTER
    assert result.decision.allowed_fields == {"visible": "safe"}
    assert result.decision.filtered_fields == ["hidden"]
    assert "insufficient_clearance" in result.decision.reasons


def test_requires_every_compartment() -> None:
    item = record(
        compartmented=DataField(
            value="controlled",
            classification=Classification.INTERNAL,
            compartments={"alpha", "bravo"},
        )
    )

    result = PolicyEngine().evaluate_record(principal(compartments={"alpha"}), item)

    assert result.decision.decision == Decision.DENY
    assert result.decision.reasons == ["missing_compartment"]


def test_non_exportable_field_never_leaves_boundary() -> None:
    item = record(
        local_only=DataField(
            value="root-key",
            classification=Classification.PUBLIC,
            exportable=False,
        )
    )

    result = PolicyEngine().evaluate_record(
        principal(Classification.RESTRICTED, {"alpha", "bravo"}), item
    )

    assert result.decision.decision == Decision.DENY
    assert result.decision.reasons == ["non_exportable"]


def test_safe_context_omits_fully_denied_records() -> None:
    denied = record(secret=DataField(value="no", classification=Classification.RESTRICTED))
    allowed = record(summary=DataField(value="yes", classification=Classification.PUBLIC))

    context, evaluations = PolicyEngine().build_safe_context(principal(), [denied, allowed])

    assert len(evaluations) == 2
    assert len(context) == 1
    assert context[0]["record_id"] == str(allowed.id)


def test_policy_preview_rejects_duplicate_record_identifiers() -> None:
    record_id = uuid4()

    with pytest.raises(ValidationError, match="must not contain duplicates"):
        PolicyPreviewRequest(record_ids=[record_id, record_id])
