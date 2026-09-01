from uuid import UUID

import pytest
from pydantic import ValidationError

from aegis.domain.models import Classification, DataField, Record
from aegis.services.record_integrity import RecordIntegrity


def make_record(*, status: str = "ready", reverse: bool = False) -> Record:
    fields = {
        "status": DataField(value=status, classification=Classification.INTERNAL),
        "code": DataField(
            value="SEALED-42",
            classification=Classification.RESTRICTED,
            exportable=False,
        ),
    }
    if reverse:
        fields = dict(reversed(list(fields.items())))
    return Record(
        id=UUID("44444444-4444-4444-8444-444444444444"),
        source="integrity-test",
        fields=fields,
    )


def test_digest_is_stable_across_field_insertion_order() -> None:
    integrity = RecordIntegrity("integrity-test-key-long-enough")
    first = integrity.digest(make_record())
    reordered = integrity.digest(make_record(reverse=True))

    assert first == reordered
    assert len(first) == 64
    assert integrity.verify(make_record(), first)


def test_digest_detects_any_record_value_change() -> None:
    integrity = RecordIntegrity("integrity-test-key-long-enough")
    original = integrity.digest(make_record())

    assert integrity.verify(make_record(status="delayed"), original) is False


def test_digest_is_bound_to_deployment_key() -> None:
    record = make_record()
    first = RecordIntegrity("first-integrity-key-long-enough").digest(record)
    second = RecordIntegrity("second-integrity-key-long-enough").digest(record)

    assert first != second


def test_record_source_is_canonical_and_never_blank() -> None:
    record = Record(source="  maintenance-ledger  ", fields={"status": DataField(value="ok")})

    assert record.source == "maintenance-ledger"
    with pytest.raises(ValidationError, match="source must not be blank"):
        Record(source="   ", fields={"status": DataField(value="ok")})
