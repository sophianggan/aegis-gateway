from aegis.services.context_budget import ContextBudget


def test_budget_retains_fields_in_deterministic_name_order() -> None:
    context = [{"record_id": "r1", "source": "test", "fields": {"z": "last", "a": "first"}}]
    full_size = ContextBudget._size({"record_id": "r1", "source": "test", "fields": {"a": "first"}})
    result = ContextBudget(full_size).apply(context)

    assert result.records[0]["fields"] == {"a": "first"}
    assert result.filtered_fields == 1
    assert result.retained_bytes <= full_size


def test_budget_drops_records_that_cannot_fit_their_envelope() -> None:
    context = [{"record_id": "r1", "source": "long-source", "fields": {"a": "value"}}]
    result = ContextBudget(10).apply(context)
    assert result.records == []
    assert result.filtered_fields == 1


def test_budget_never_exceeds_configured_serialized_size() -> None:
    context = [
        {"record_id": f"r{index}", "source": "test", "fields": {"value": "x" * 100}}
        for index in range(10)
    ]
    result = ContextBudget(400).apply(context)
    assert result.retained_bytes <= 400
    assert result.filtered_fields > 0
