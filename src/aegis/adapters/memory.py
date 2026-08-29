from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator, Sequence
from uuid import UUID

from aegis.domain.models import AuditEvent, Record


class InMemoryRecordRepository:
    def __init__(self, records: Sequence[Record] = ()) -> None:
        self._records = {record.id: record for record in records}

    async def healthcheck(self) -> bool:
        return True

    async def fetch(self, record_ids: Sequence[UUID], *, limit: int) -> list[Record]:
        return [self._records[item] for item in record_ids[:limit] if item in self._records]

    async def put(self, record: Record) -> None:
        self._records[record.id] = record


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self._events: dict[UUID, list[AuditEvent]] = defaultdict(list)

    async def append(self, event: AuditEvent) -> None:
        events = self._events[event.request_id]
        if events and event.sequence != events[-1].sequence + 1:
            raise ValueError("audit sequence must increase monotonically")
        if not events and event.sequence != 0:
            raise ValueError("first audit sequence must be zero")
        events.append(event)

    async def latest(self, request_id: UUID) -> AuditEvent | None:
        events = self._events.get(request_id, [])
        return events[-1] if events else None

    async def stream(self, request_id: UUID) -> AsyncIterator[AuditEvent]:
        for event in self._events.get(request_id, []):
            yield event

    async def page(self, request_id: UUID, *, after_sequence: int, limit: int) -> list[AuditEvent]:
        return [
            event for event in self._events.get(request_id, []) if event.sequence > after_sequence
        ][:limit]


class InMemoryRevocationStore:
    def __init__(self, revoked: set[str] | None = None) -> None:
        self._revoked = revoked or set()

    async def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked

    def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)
