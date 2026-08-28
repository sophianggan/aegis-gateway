from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Protocol
from uuid import UUID

from aegis.domain.models import AuditEvent, Record


class RecordRepository(Protocol):
    async def healthcheck(self) -> bool: ...

    async def fetch(self, record_ids: Sequence[UUID], *, limit: int) -> list[Record]: ...

    async def put(self, record: Record) -> None: ...


class AuditRepository(Protocol):
    async def append(self, event: AuditEvent) -> None: ...

    async def latest(self, request_id: UUID) -> AuditEvent | None: ...

    def stream(self, request_id: UUID) -> AsyncIterator[AuditEvent]: ...


class ModelProvider(Protocol):
    async def complete(self, *, system: str, user: str, request_id: UUID) -> str: ...


class RevocationStore(Protocol):
    async def is_revoked(self, token_id: str) -> bool: ...


class RateLimiter(Protocol):
    async def enforce(self, identity: str) -> None: ...
