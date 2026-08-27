from uuid import uuid4

from aegis.adapters.memory import InMemoryAuditRepository
from aegis.domain.models import AuditAction, Decision
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
