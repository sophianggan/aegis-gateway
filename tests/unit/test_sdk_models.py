from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegis_sdk import (
    AuditBundle,
    AuditCheckpoint,
    AuditPage,
    Classification,
    ClassifiedValue,
    QueryResult,
    RecordDeletionReceipt,
    RecordInput,
    RecordReceipt,
    TokenRevocationReceipt,
)


def test_sdk_record_normalizes_source_and_compartments() -> None:
    record = RecordInput(
        source="  work-orders  ",
        fields={
            "status": ClassifiedValue(
                value="open",
                compartments={" Operations ", "operations", "  "},
            )
        },
    )

    assert record.source == "work-orders"
    assert record.fields["status"].compartments == {"operations"}


@pytest.mark.parametrize("source", ["", "   "])
def test_sdk_record_rejects_blank_source(source: str) -> None:
    with pytest.raises(ValidationError, match="source must not be blank"):
        RecordInput(source=source, fields={"status": ClassifiedValue(value="open")})


@pytest.mark.parametrize("field_name", ["", "x" * 65, "0status", "bad field", "line\nbreak"])
def test_sdk_record_rejects_unsafe_field_names(field_name: str) -> None:
    with pytest.raises(ValidationError, match="field names"):
        RecordInput(source="work-orders", fields={field_name: ClassifiedValue(value="open")})


def test_sdk_record_rejects_oversized_compartment_name() -> None:
    with pytest.raises(ValidationError, match="compartment names"):
        ClassifiedValue(value="open", compartments={"x" * 65})


def test_sdk_record_rejects_too_many_compartments() -> None:
    with pytest.raises(ValidationError, match="at most 50 items"):
        ClassifiedValue(
            value="open",
            compartments={f"compartment-{index}" for index in range(51)},
        )


def test_sdk_record_rejects_string_as_compartment_collection() -> None:
    with pytest.raises(ValidationError, match="valid set"):
        ClassifiedValue(value="open", compartments="operations")  # type: ignore[arg-type]


@pytest.mark.parametrize("compartments", [["operations", 7], [None], [True]])
def test_sdk_record_rejects_non_string_compartment_items(compartments: object) -> None:
    with pytest.raises(ValidationError, match="must contain only strings"):
        ClassifiedValue(value="open", compartments=compartments)  # type: ignore[arg-type]


@pytest.mark.parametrize("exportable", [0, 1, "false", "true"])
def test_sdk_record_rejects_coerced_exportable_flags(exportable: object) -> None:
    with pytest.raises(ValidationError, match="valid boolean"):
        ClassifiedValue(value="open", exportable=exportable)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [0, 1, "false", "true"])
def test_sdk_responses_reject_coerced_booleans(value: object) -> None:
    request_id = uuid4()
    with pytest.raises(ValidationError, match="valid boolean"):
        RecordDeletionReceipt(
            request_id=request_id,
            record_id=uuid4(),
            deleted=value,  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="valid boolean"):
        TokenRevocationReceipt(
            request_id=request_id,
            revoked=value,  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="valid boolean"):
        AuditPage(events=[], next_sequence=None, has_more=value)  # type: ignore[arg-type]


def invalid_count_responses(value: object) -> list[Callable[[], object]]:
    request_id = uuid4()
    return [
        lambda: RecordReceipt(
            request_id=request_id,
            record_id=uuid4(),
            field_count=value,  # type: ignore[arg-type]
            highest_classification=Classification.INTERNAL,
            integrity_algorithm="HMAC-SHA256",
            integrity_digest="0" * 64,
        ),
        lambda: QueryResult(
            request_id=request_id,
            answer="ok",
            citations=[],
            filtered_field_count=value,  # type: ignore[arg-type]
            policy_summary="passed",
        ),
        lambda: AuditBundle(
            version="aegis.audit.v1",
            request_id=request_id,
            generated_at=datetime.now(UTC),
            event_count=value,  # type: ignore[arg-type]
            chain_head="0" * 64,
            events=[],
            signature_algorithm="HMAC-SHA256",
            bundle_signature="0" * 64,
        ),
        lambda: AuditCheckpoint(
            version="aegis.checkpoint.v1",
            request_id=request_id,
            generated_at=datetime.now(UTC),
            event_count=value,  # type: ignore[arg-type]
            chain_head="0" * 64,
            signature_algorithm="HMAC-SHA256",
            signature="0" * 64,
        ),
    ]


@pytest.mark.parametrize(
    ("value", "message"),
    [(-1, "greater than or equal"), ("1", "valid integer")],
)
def test_sdk_responses_reject_invalid_counts(value: object, message: str) -> None:
    for factory in invalid_count_responses(value):
        with pytest.raises(ValidationError, match=message):
            factory()


def test_sdk_record_receipt_rejects_zero_fields() -> None:
    factory = invalid_count_responses(0)[0]
    with pytest.raises(ValidationError, match="greater than or equal"):
        factory()
