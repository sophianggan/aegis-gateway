from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from typing import Any
from uuid import UUID

import asyncpg

from aegis.domain.models import AuditEvent, Record


def _decode_json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class PostgresRecordRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def healthcheck(self) -> bool:
        return bool(await self._pool.fetchval("SELECT 1"))

    async def fetch(self, record_ids: Sequence[UUID], *, limit: int) -> list[Record]:
        if not record_ids:
            return []
        rows = await self._pool.fetch(
            """
            SELECT id, source, fields, created_at
            FROM records
            WHERE id = ANY($1::uuid[])
            ORDER BY array_position($1::uuid[], id)
            LIMIT $2
            """,
            list(record_ids),
            limit,
        )
        return [
            Record(
                id=row["id"],
                source=row["source"],
                fields=_decode_json(row["fields"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def put(self, record: Record) -> None:
        await self._pool.execute(
            """
            INSERT INTO records (id, source, fields, created_at)
            VALUES ($1, $2, $3::jsonb, $4)
            ON CONFLICT (id) DO UPDATE
            SET source = EXCLUDED.source, fields = EXCLUDED.fields
            """,
            record.id,
            record.source,
            json.dumps(
                {name: field.model_dump(mode="json") for name, field in record.fields.items()},
                separators=(",", ":"),
            ),
            record.created_at,
        )

    async def delete(self, record_id: UUID) -> bool:
        status = await self._pool.execute("DELETE FROM records WHERE id = $1", record_id)
        return str(status) == "DELETE 1"


class PostgresAuditRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def append(self, event: AuditEvent) -> None:
        await self._pool.execute(
            """
            INSERT INTO audit_events (
                id, request_id, sequence, occurred_at, actor, action, decision,
                resource_ids, details, previous_hash, event_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11)
            """,
            event.id,
            event.request_id,
            event.sequence,
            event.occurred_at,
            event.actor,
            event.action.value,
            event.decision.value,
            json.dumps(event.resource_ids, separators=(",", ":")),
            json.dumps(event.details, separators=(",", ":"), default=str),
            event.previous_hash,
            event.event_hash,
        )

    async def latest(self, request_id: UUID) -> AuditEvent | None:
        row = await self._pool.fetchrow(
            """
            SELECT * FROM audit_events
            WHERE request_id = $1
            ORDER BY sequence DESC
            LIMIT 1
            """,
            request_id,
        )
        return self._to_event(row) if row else None

    async def stream(self, request_id: UUID) -> AsyncIterator[AuditEvent]:
        rows = await self._pool.fetch(
            "SELECT * FROM audit_events WHERE request_id = $1 ORDER BY sequence",
            request_id,
        )
        for row in rows:
            yield self._to_event(row)

    async def page(self, request_id: UUID, *, after_sequence: int, limit: int) -> list[AuditEvent]:
        rows = await self._pool.fetch(
            """
            SELECT * FROM audit_events
            WHERE request_id = $1 AND sequence > $2
            ORDER BY sequence
            LIMIT $3
            """,
            request_id,
            after_sequence,
            limit,
        )
        return [self._to_event(row) for row in rows]

    @staticmethod
    def _to_event(row: asyncpg.Record) -> AuditEvent:
        return AuditEvent(
            id=row["id"],
            request_id=row["request_id"],
            sequence=row["sequence"],
            occurred_at=row["occurred_at"],
            actor=row["actor"],
            action=row["action"],
            decision=row["decision"],
            resource_ids=_decode_json(row["resource_ids"]),
            details=_decode_json(row["details"]),
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )


class PostgresRevocationStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def is_revoked(self, token_id: str) -> bool:
        value = await self._pool.fetchval(
            "SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_id = $1)", token_id
        )
        return bool(value)

    async def revoke(self, token_id: str, *, reason: str) -> None:
        await self._pool.execute(
            """
            INSERT INTO revoked_tokens (token_id, reason)
            VALUES ($1, $2)
            ON CONFLICT (token_id) DO UPDATE
            SET revoked_at = now(), reason = EXCLUDED.reason
            """,
            token_id,
            reason,
        )
