from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegis.adapters.memory import InMemoryAuditRepository
from aegis.domain.models import AuditAction, AuditCheckpoint, Decision
from aegis.errors import AuditIntegrityError
from aegis.services.audit import AuditTrail


async def test_builds_and_verifies_a_hash_chain() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "audit-test-key-that-is-long")
    request_id = uuid4()

    first = await trail.record(
        request_id=request_id,
        actor="analyst",
        action=AuditAction.AUTHENTICATE,
        decision=Decision.ALLOW,
    )
    second = await trail.record(
        request_id=request_id,
        actor="analyst",
        action=AuditAction.RETRIEVE,
        decision=Decision.FILTER,
        details={"filtered": 2},
    )

    assert first.sequence == 0
    assert second.sequence == 1
    assert second.previous_hash == first.event_hash
    assert len(first.event_hash) == 64
    assert await trail.verify(request_id)


async def test_detects_event_tampering() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "audit-test-key-that-is-long")
    request_id = uuid4()
    event = await trail.record(
        request_id=request_id,
        actor="analyst",
        action=AuditAction.REQUEST_COMPLETE,
        decision=Decision.ALLOW,
    )
    repository._events[request_id][0] = event.model_copy(update={"actor": "intruder"})

    assert not await trail.verify(request_id)


async def test_empty_chain_is_not_valid() -> None:
    trail = AuditTrail(InMemoryAuditRepository(), "audit-test-key-that-is-long")
    assert not await trail.verify(uuid4())


async def test_exports_signed_self_consistent_bundle() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "audit-test-key-that-is-long")
    request_id = uuid4()
    await trail.record(
        request_id=request_id,
        actor="auditor",
        action=AuditAction.REQUEST_COMPLETE,
        decision=Decision.ALLOW,
    )

    bundle = await trail.export(request_id)

    assert bundle.event_count == 1
    assert bundle.chain_head == bundle.events[0].event_hash
    assert len(bundle.bundle_signature) == 64
    assert trail.verify_bundle(bundle)


async def test_bundle_verification_detects_metadata_tampering() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "audit-test-key-that-is-long")
    request_id = uuid4()
    await trail.record(
        request_id=request_id,
        actor="auditor",
        action=AuditAction.REQUEST_COMPLETE,
        decision=Decision.ALLOW,
    )
    bundle = await trail.export(request_id)

    tampered = bundle.model_copy(update={"chain_head": "0" * 64})
    assert not trail.verify_bundle(tampered)


async def test_refuses_to_export_tampered_chain() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "audit-test-key-that-is-long")
    request_id = uuid4()
    event = await trail.record(
        request_id=request_id,
        actor="auditor",
        action=AuditAction.REQUEST_COMPLETE,
        decision=Decision.ALLOW,
    )
    repository._events[request_id][0] = event.model_copy(update={"actor": "changed"})

    with pytest.raises(AuditIntegrityError):
        await trail.export(request_id)


async def test_signed_checkpoint_pins_verified_chain_head() -> None:
    repository = InMemoryAuditRepository()
    trail = AuditTrail(repository, "checkpoint-signing-key-long-enough")
    request_id = uuid4()
    event = await trail.record(
        request_id=request_id,
        actor="reviewer",
        action=AuditAction.REQUEST_COMPLETE,
        decision=Decision.ALLOW,
    )

    checkpoint = await trail.checkpoint(request_id)

    assert checkpoint.event_count == 1
    assert checkpoint.chain_head == event.event_hash
    assert len(checkpoint.signature) == 64
    assert trail.verify_checkpoint(checkpoint)
    assert not trail.verify_checkpoint(checkpoint.model_copy(update={"event_count": 2}))


async def test_checkpoint_rejects_missing_chain() -> None:
    trail = AuditTrail(InMemoryAuditRepository(), "checkpoint-signing-key-long-enough")
    with pytest.raises(AuditIntegrityError):
        await trail.checkpoint(uuid4())


def test_checkpoint_schema_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValidationError, match="HMAC-SHA256"):
        AuditCheckpoint(
            request_id=uuid4(),
            event_count=1,
            chain_head="0" * 64,
            signature_algorithm="none",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("after_sequence", "limit", "message"),
    [
        (-2, 50, "after_sequence must be at least -1"),
        (-1, 0, "limit must be between 1 and 200"),
        (-1, 201, "limit must be between 1 and 200"),
    ],
)
async def test_audit_page_rejects_invalid_bounds(
    after_sequence: int, limit: int, message: str
) -> None:
    trail = AuditTrail(InMemoryAuditRepository(), "audit-test-key-that-is-long")

    with pytest.raises(ValueError, match=message):
        await trail.page(uuid4(), after_sequence=after_sequence, limit=limit)


@pytest.mark.parametrize(
    ("parameter", "value", "message"),
    [
        ("after_sequence", True, "integer at least -1"),
        ("after_sequence", 1.5, "integer at least -1"),
        ("limit", True, "integer between 1 and 200"),
        ("limit", 1.5, "integer between 1 and 200"),
    ],
)
async def test_audit_page_rejects_non_integer_bounds(
    parameter: str, value: object, message: str
) -> None:
    trail = AuditTrail(InMemoryAuditRepository(), "audit-test-key-that-is-long")

    with pytest.raises(ValueError, match=message):
        await trail.page(uuid4(), **{parameter: value})  # type: ignore[arg-type]
