from __future__ import annotations

import math
from collections import Counter, defaultdict
from threading import Lock


class MetricsRegistry:
    """Low-cardinality Prometheus metrics that never retain request payloads."""

    _buckets = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

    def __init__(self) -> None:
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._durations: Counter[tuple[str, str, float]] = Counter()
        self._duration_sum: defaultdict[tuple[str, str], float] = defaultdict(float)
        self._lock = Lock()

    def observe_http(self, *, method: str, route: str, status: int, duration: float) -> None:
        normalized_method = method.upper()[:12]
        normalized_route = route if route.startswith("/") else "unmatched"
        key = (normalized_method, normalized_route)
        with self._lock:
            self._requests[(normalized_method, normalized_route, status)] += 1
            self._duration_sum[key] += duration
            for boundary in self._buckets:
                if duration <= boundary:
                    self._durations[(normalized_method, normalized_route, boundary)] += 1
            self._durations[(normalized_method, normalized_route, math.inf)] += 1

    @staticmethod
    def _label(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    def render(self) -> str:
        with self._lock:
            requests = self._requests.copy()
            durations = self._durations.copy()
            duration_sum = self._duration_sum.copy()

        lines = [
            "# HELP aegis_build_info Static gateway build information.",
            "# TYPE aegis_build_info gauge",
            'aegis_build_info{version="0.1.0"} 1',
            "# HELP aegis_http_requests_total Completed HTTP requests.",
            "# TYPE aegis_http_requests_total counter",
        ]
        for (method, route, status), count in sorted(requests.items()):
            lines.append(
                "aegis_http_requests_total"
                f'{{method="{self._label(method)}",route="{self._label(route)}",'
                f'status="{status}"}} {count}'
            )
        lines.extend(
            [
                "# HELP aegis_http_request_duration_seconds Request duration by route.",
                "# TYPE aegis_http_request_duration_seconds histogram",
            ]
        )
        for method, route in sorted(duration_sum):
            for boundary in (*self._buckets, math.inf):
                label = "+Inf" if math.isinf(boundary) else str(boundary)
                count = durations[(method, route, boundary)]
                lines.append(
                    "aegis_http_request_duration_seconds_bucket"
                    f'{{method="{self._label(method)}",route="{self._label(route)}",'
                    f'le="{label}"}} {count}'
                )
            total = sum(
                count
                for (request_method, request_route, _), count in requests.items()
                if request_method == method and request_route == route
            )
            lines.append(
                "aegis_http_request_duration_seconds_sum"
                f'{{method="{self._label(method)}",route="{self._label(route)}"}} '
                f"{duration_sum[(method, route)]:.9f}"
            )
            lines.append(
                "aegis_http_request_duration_seconds_count"
                f'{{method="{self._label(method)}",route="{self._label(route)}"}} {total}'
            )
        return "\n".join(lines) + "\n"
