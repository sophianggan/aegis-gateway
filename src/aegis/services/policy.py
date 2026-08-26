from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.domain.models import Decision, PolicyDecision, Principal, Record


@dataclass(frozen=True)
class EvaluatedRecord:
    record: Record
    decision: PolicyDecision


class PolicyEngine:
    """Apply mandatory access control at field granularity.

    Access requires both sufficient clearance and every field compartment. Values
    marked non-exportable remain inside the data boundary regardless of clearance.
    """

    def evaluate_record(self, principal: Principal, record: Record) -> EvaluatedRecord:
        allowed: dict[str, Any] = {}
        filtered: list[str] = []
        reasons: set[str] = set()

        for name, field in record.fields.items():
            if not field.exportable:
                filtered.append(name)
                reasons.add("non_exportable")
                continue
            if principal.clearance < field.classification:
                filtered.append(name)
                reasons.add("insufficient_clearance")
                continue
            missing = field.compartments - principal.compartments
            if missing:
                filtered.append(name)
                reasons.add("missing_compartment")
                continue
            allowed[name] = field.value

        if allowed and filtered:
            decision = Decision.FILTER
        elif allowed:
            decision = Decision.ALLOW
        else:
            decision = Decision.DENY

        return EvaluatedRecord(
            record=record,
            decision=PolicyDecision(
                decision=decision,
                allowed_fields=allowed,
                filtered_fields=sorted(filtered),
                reasons=sorted(reasons),
            ),
        )

    def build_safe_context(
        self, principal: Principal, records: list[Record]
    ) -> tuple[list[dict[str, Any]], list[EvaluatedRecord]]:
        evaluated = [self.evaluate_record(principal, record) for record in records]
        context = [
            {
                "record_id": str(item.record.id),
                "source": item.record.source,
                "fields": item.decision.allowed_fields,
            }
            for item in evaluated
            if item.decision.allowed_fields
        ]
        return context, evaluated

