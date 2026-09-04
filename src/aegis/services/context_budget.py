from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BudgetedContext:
    records: list[dict[str, Any]]
    retained_bytes: int
    filtered_fields: int


class ContextBudget:
    """Bound serialized context while preserving deterministic field selection."""

    def __init__(self, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("context budget must be positive")
        self._max_bytes = max_bytes

    @staticmethod
    def _size(value: object) -> int:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        return len(encoded)

    def apply(self, context: list[dict[str, Any]]) -> BudgetedContext:
        retained: list[dict[str, Any]] = []
        filtered = 0
        for item in context:
            shell = {"record_id": item["record_id"], "source": item["source"], "fields": {}}
            if self._size([*retained, shell]) > self._max_bytes:
                filtered += len(item["fields"])
                continue
            kept_fields: dict[str, Any] = {}
            for name in sorted(item["fields"]):
                candidate = {**shell, "fields": {**kept_fields, name: item["fields"][name]}}
                if self._size([*retained, candidate]) <= self._max_bytes:
                    kept_fields[name] = item["fields"][name]
                else:
                    filtered += 1
            if kept_fields:
                retained.append({**shell, "fields": kept_fields})
        return BudgetedContext(
            records=retained,
            retained_bytes=self._size(retained),
            filtered_fields=filtered,
        )
