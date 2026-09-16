import math

import pytest

from aegis.services.metrics import MetricsRegistry


def test_renders_counters_and_cumulative_histogram() -> None:
    registry = MetricsRegistry()
    registry.observe_http(method="get", route="/v1/query", status=200, duration=0.02)
    registry.observe_http(method="GET", route="/v1/query", status=429, duration=0.2)

    output = registry.render()

    assert 'status="200"} 1' in output
    assert 'status="429"} 1' in output
    assert 'le="0.025"} 1' in output
    assert 'le="0.25"} 2' in output
    assert 'le="+Inf"} 2' in output
    assert "aegis_http_request_duration_seconds_count" in output


def test_escapes_label_values_and_bounds_method_cardinality() -> None:
    registry = MetricsRegistry()
    registry.observe_http(
        method='unexpected-method-name"',
        route='/unsafe\nroute"',
        status=404,
        duration=10,
    )
    output = registry.render()
    assert "UNEXPECTED-M" in output
    assert '\\nroute\\"' in output
    assert 'route="unmatched"' not in output


@pytest.mark.parametrize("duration", [-0.001, math.nan, math.inf, -math.inf])
def test_rejects_invalid_durations(duration: float) -> None:
    registry = MetricsRegistry()

    with pytest.raises(ValueError, match="finite and non-negative"):
        registry.observe_http(method="GET", route="/health", status=200, duration=duration)

    assert 'method="GET"' not in registry.render()


@pytest.mark.parametrize("status", [99, 600, True, 200.0, "200"])
def test_rejects_invalid_http_statuses(status: object) -> None:
    registry = MetricsRegistry()

    with pytest.raises(ValueError, match="integer between 100 and 599"):
        registry.observe_http(
            method="GET",
            route="/health",
            status=status,  # type: ignore[arg-type]
            duration=0.01,
        )

    assert 'method="GET"' not in registry.render()
