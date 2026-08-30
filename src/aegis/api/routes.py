import asyncio
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from aegis.api.dependencies import get_container, get_principal
from aegis.container import Container
from aegis.domain.models import (
    AuditAction,
    AuditBundle,
    AuditCheckpoint,
    AuditEvent,
    AuditPage,
    Decision,
    PolicyPreviewRequest,
    PolicyPreviewResponse,
    Principal,
    QueryRequest,
    QueryResponse,
    Record,
    RecordCreate,
    RecordDeletionReceipt,
    RecordReceipt,
    TokenRevocationReceipt,
    TokenRevocationRequest,
)
from aegis.errors import AuthenticationError, AuthorizationError

router = APIRouter(prefix="/v1")


async def _enforce_operational_access(
    principal: Principal,
    container: Container,
    *,
    required_role: str,
) -> None:
    if principal.token_id and await container.revocations.is_revoked(principal.token_id):
        raise AuthenticationError("token has been revoked")
    await container.rate_limiter.enforce(principal.subject)
    if required_role not in principal.roles:
        raise AuthorizationError(f"{required_role} role is required")


@router.get("/health/live", tags=["operations"])
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", tags=["operations"], response_model=None)
async def readiness(request: Request) -> dict[str, object] | JSONResponse:
    container = get_container(request)
    try:
        async with asyncio.timeout(min(container.settings.request_timeout_seconds, 2.0)):
            persistence_ready = await container.records.healthcheck()
    except (TimeoutError, OSError, RuntimeError):
        persistence_ready = False
    body: dict[str, object] = {
        "status": "ready" if persistence_ready else "degraded",
        "checks": {"persistence": "ok" if persistence_ready else "unavailable"},
    }
    if not persistence_ready:
        return JSONResponse(status_code=503, content=body)
    return body


@router.post("/query", response_model=QueryResponse, tags=["gateway"])
async def query(
    payload: QueryRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> QueryResponse:
    return await container.queries.execute(principal, payload)


@router.post("/policy/preview", response_model=PolicyPreviewResponse, tags=["policy"])
async def preview_policy(
    payload: PolicyPreviewRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> PolicyPreviewResponse:
    await _enforce_operational_access(principal, container, required_role="policy-reviewer")
    return await container.policy_previews.execute(principal, payload)


@router.get("/audit/{request_id}", response_model=list[AuditEvent], tags=["audit"])
async def audit_events(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> list[AuditEvent]:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return [event async for event in container.audit.stream(request_id)]


@router.get("/audit/{request_id}/events", response_model=AuditPage, tags=["audit"])
async def paginated_audit_events(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
    after_sequence: Annotated[int, Query(ge=-1)] = -1,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AuditPage:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return await container.audit.page(request_id, after_sequence=after_sequence, limit=limit)


@router.get("/audit/{request_id}/verify", tags=["audit"])
async def verify_audit_chain(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> dict[str, bool]:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return {"valid": await container.audit.verify(request_id)}


@router.get("/audit/{request_id}/export", response_model=AuditBundle, tags=["audit"])
async def export_audit_bundle(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> AuditBundle:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return await container.audit.export(request_id)


@router.get("/audit/{request_id}/checkpoint", response_model=AuditCheckpoint, tags=["audit"])
async def create_audit_checkpoint(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> AuditCheckpoint:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return await container.audit.checkpoint(request_id)


@router.post("/records", response_model=RecordReceipt, status_code=201, tags=["records"])
async def create_record(
    payload: RecordCreate,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> RecordReceipt:
    await _enforce_operational_access(principal, container, required_role="data-admin")
    record = Record(id=payload.id, source=payload.source, fields=payload.fields)
    await container.records.put(record)
    request_id = uuid4()
    integrity_digest = container.record_integrity.digest(record)
    highest = max(field.classification for field in record.fields.values())
    await container.audit.record(
        request_id=request_id,
        actor=principal.subject,
        action=AuditAction.RECORD_UPSERT,
        decision=Decision.ALLOW,
        resource_ids=[str(record.id)],
        details={
            "field_count": len(record.fields),
            "highest_classification": highest.name,
            "source": record.source,
            "integrity_algorithm": "HMAC-SHA256",
            "integrity_digest": integrity_digest,
        },
    )
    return RecordReceipt(
        request_id=request_id,
        record_id=record.id,
        field_count=len(record.fields),
        highest_classification=highest,
        integrity_digest=integrity_digest,
    )


@router.delete("/records/{record_id}", response_model=RecordDeletionReceipt, tags=["records"])
async def delete_record(
    record_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> RecordDeletionReceipt:
    await _enforce_operational_access(principal, container, required_role="data-admin")
    request_id = uuid4()
    deleted = await container.records.delete(record_id)
    await container.audit.record(
        request_id=request_id,
        actor=principal.subject,
        action=AuditAction.RECORD_DELETE,
        decision=Decision.ALLOW if deleted else Decision.DENY,
        resource_ids=[str(record_id)],
        details={"deleted": deleted},
    )
    return RecordDeletionReceipt(request_id=request_id, record_id=record_id, deleted=deleted)


@router.post(
    "/admin/token-revocations",
    response_model=TokenRevocationReceipt,
    status_code=201,
    tags=["administration"],
)
async def revoke_token(
    payload: TokenRevocationRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> TokenRevocationReceipt:
    await _enforce_operational_access(principal, container, required_role="security-admin")
    request_id = uuid4()
    await container.revocations.revoke(payload.token_id, reason=payload.reason_code)
    await container.audit.record(
        request_id=request_id,
        actor=principal.subject,
        action=AuditAction.TOKEN_REVOKE,
        decision=Decision.ALLOW,
        details={"reason_code": payload.reason_code},
    )
    return TokenRevocationReceipt(request_id=request_id)
