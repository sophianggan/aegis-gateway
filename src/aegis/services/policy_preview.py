from __future__ import annotations

from uuid import uuid4

from aegis.domain.models import (
    AuditAction,
    Decision,
    PolicyPreviewRequest,
    PolicyPreviewResponse,
    Principal,
    RecordPolicyPreview,
)
from aegis.ports import RecordRepository
from aegis.services.audit import AuditTrail
from aegis.services.policy import PolicyEngine


class PolicyPreviewService:
    """Explain access decisions without disclosing classified field values."""

    def __init__(
        self,
        *,
        records: RecordRepository,
        policy: PolicyEngine,
        audit: AuditTrail,
        max_records: int,
    ) -> None:
        self._records = records
        self._policy = policy
        self._audit = audit
        self._max_records = max_records

    async def execute(
        self, principal: Principal, payload: PolicyPreviewRequest
    ) -> PolicyPreviewResponse:
        request_id = uuid4()
        records = await self._records.fetch(payload.record_ids, limit=self._max_records)
        found_ids = {record.id for record in records}
        missing = [item for item in payload.record_ids if item not in found_ids]
        previews: list[RecordPolicyPreview] = []
        for record in records:
            result = self._policy.evaluate_record(principal, record).decision
            previews.append(
                RecordPolicyPreview(
                    record_id=record.id,
                    source=record.source,
                    decision=result.decision,
                    allowed_fields=sorted(result.allowed_fields),
                    filtered_fields=result.filtered_fields,
                    reasons=result.reasons,
                )
            )
        overall = Decision.ALLOW
        if any(item.decision == Decision.DENY for item in previews):
            overall = Decision.DENY
        elif missing or any(item.decision == Decision.FILTER for item in previews):
            overall = Decision.FILTER
        await self._audit.record(
            request_id=request_id,
            actor=principal.subject,
            action=AuditAction.POLICY_PREVIEW,
            decision=overall,
            resource_ids=[str(item) for item in payload.record_ids],
            details={
                "record_count": len(previews),
                "missing_count": len(missing),
                "allowed_field_count": sum(len(item.allowed_fields) for item in previews),
                "filtered_field_count": sum(len(item.filtered_fields) for item in previews),
            },
        )
        return PolicyPreviewResponse(
            request_id=request_id, records=previews, missing_record_ids=missing
        )
