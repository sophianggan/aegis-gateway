from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

from aegis.domain.models import AuditAction, AuditBundle, AuditEvent, Decision
from aegis.errors import AuditIntegrityError
from aegis.ports import AuditRepository


class AuditTrail:
    """Append and verify HMAC-linked events without storing sensitive payloads."""

    def __init__(self, repository: AuditRepository, signing_key: str) -> None:
        if len(signing_key) < 16:
            raise ValueError("audit signing key must contain at least 16 characters")
        self._repository = repository
        self._key = signing_key.encode()

    def _signature(self, event: AuditEvent) -> str:
        payload = event.model_dump(mode="json", exclude={"event_hash"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()

    async def record(
        self,
        *,
        request_id: UUID,
        actor: str,
        action: AuditAction,
        decision: Decision,
        resource_ids: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        previous = await self._repository.latest(request_id)
        event = AuditEvent(
            request_id=request_id,
            sequence=previous.sequence + 1 if previous else 0,
            actor=actor,
            action=action,
            decision=decision,
            resource_ids=resource_ids or [],
            details=details or {},
            previous_hash=previous.event_hash if previous else "",
        )
        signed = event.model_copy(update={"event_hash": self._signature(event)})
        await self._repository.append(signed)
        return signed

    async def verify(self, request_id: UUID) -> bool:
        events = [event async for event in self._repository.stream(request_id)]
        return self._verify_events(events)

    def _verify_events(self, events: list[AuditEvent]) -> bool:
        expected_previous = ""
        expected_sequence = 0
        for event in events:
            if event.sequence != expected_sequence or event.previous_hash != expected_previous:
                return False
            unsigned = event.model_copy(update={"event_hash": ""})
            if not hmac.compare_digest(event.event_hash, self._signature(unsigned)):
                return False
            expected_previous = event.event_hash
            expected_sequence += 1
        return expected_sequence > 0

    def _bundle_signature(self, bundle: AuditBundle) -> str:
        payload = bundle.model_dump(mode="json", exclude={"bundle_signature"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()

    async def export(self, request_id: UUID) -> AuditBundle:
        events = [event async for event in self._repository.stream(request_id)]
        if not self._verify_events(events):
            raise AuditIntegrityError("audit chain cannot be exported because verification failed")
        bundle = AuditBundle(
            request_id=request_id,
            event_count=len(events),
            chain_head=events[-1].event_hash,
            events=events,
        )
        return bundle.model_copy(update={"bundle_signature": self._bundle_signature(bundle)})

    def verify_bundle(self, bundle: AuditBundle) -> bool:
        if bundle.event_count != len(bundle.events) or not bundle.events:
            return False
        if bundle.request_id != bundle.events[0].request_id:
            return False
        if any(event.request_id != bundle.request_id for event in bundle.events):
            return False
        if bundle.chain_head != bundle.events[-1].event_hash:
            return False
        if not self._verify_events(bundle.events):
            return False
        unsigned = bundle.model_copy(update={"bundle_signature": ""})
        return hmac.compare_digest(bundle.bundle_signature, self._bundle_signature(unsigned))

    async def stream(self, request_id: UUID) -> AsyncIterator[AuditEvent]:
        async for event in self._repository.stream(request_id):
            yield event
