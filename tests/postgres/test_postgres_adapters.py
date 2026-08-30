import os
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest

from aegis.adapters.postgres import (
    PostgresAuditRepository,
    PostgresRecordRepository,
    PostgresRevocationStore,
)
from aegis.domain.models import (
    AuditAction,
    Classification,
    DataField,
    Decision,
    Record,
)
from aegis.services.audit import AuditTrail

MIGRATIONS = [path.read_text() for path in sorted(Path("migrations").glob("*.sql"))]


@pytest.mark.postgres
async def test_postgres_adapters_preserve_policy_metadata_and_audit_integrity() -> None:
    database_url = os.environ.get("AEGIS_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AEGIS_TEST_DATABASE_URL is not configured")

    connection = await asyncpg.connect(database_url)
    try:
        for migration in MIGRATIONS:
            await connection.execute(migration)
    finally:
        await connection.close()

    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=3)
    try:
        records = PostgresRecordRepository(pool)
        record = Record(
            id=uuid4(),
            source="integration-test",
            fields={
                "summary": DataField(
                    value="inspection passed",
                    classification=Classification.INTERNAL,
                    compartments=frozenset({"operations"}),
                ),
                "local_only": DataField(
                    value="CONTROLLED-9917",
                    classification=Classification.RESTRICTED,
                    exportable=False,
                ),
            },
        )
        await records.put(record)
        loaded = await records.fetch([record.id], limit=1)
        assert loaded == [record]
        assert loaded[0].fields["summary"].compartments == {"operations"}
        assert not loaded[0].fields["local_only"].exportable

        audit_repository = PostgresAuditRepository(pool)
        audit = AuditTrail(audit_repository, "postgres-integration-audit-key")
        request_id = uuid4()
        first = await audit.record(
            request_id=request_id,
            actor="integration-test",
            action=AuditAction.AUTHENTICATE,
            decision=Decision.ALLOW,
        )
        await audit.record(
            request_id=request_id,
            actor="integration-test",
            action=AuditAction.REQUEST_COMPLETE,
            decision=Decision.ALLOW,
            resource_ids=[str(record.id)],
        )
        assert await audit.verify(request_id)
        latest = await audit_repository.latest(request_id)
        assert latest is not None
        assert latest.sequence == 1

        with pytest.raises(asyncpg.RaiseError, match="append-only"):
            await pool.execute(
                "UPDATE audit_events SET actor = 'changed' WHERE id = $1",
                first.id,
            )

        token_reference = f"revoked-{uuid4()}"
        await pool.execute(
            "INSERT INTO revoked_tokens (token_id, reason) VALUES ($1, $2)",
            token_reference,
            "integration test",
        )
        revocations = PostgresRevocationStore(pool)
        assert await revocations.is_revoked(token_reference)
        assert not await revocations.is_revoked(f"active-{uuid4()}")
        new_reference = f"api-revoked-{uuid4()}"
        await revocations.revoke(new_reference, reason="suspected-compromise")
        assert await revocations.is_revoked(new_reference)
    finally:
        await pool.close()
