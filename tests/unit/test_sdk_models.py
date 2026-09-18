import pytest
from pydantic import ValidationError

from aegis_sdk import ClassifiedValue, RecordInput


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
