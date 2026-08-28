from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request

from aegis.api.dependencies import get_container, get_principal
from aegis.container import Container
from aegis.domain.models import (
    AuditAction,
    AuditBundle,
    AuditEvent,
    Decision,
    Principal,
    QueryRequest,
    QueryResponse,
    Record,
    RecordCreate,
    RecordReceipt,
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


@router.get("/health/ready", tags=["operations"])
async def readiness(request: Request) -> dict[str, str]:
    get_container(request)
    return {"status": "ready"}


@router.post("/query", response_model=QueryResponse, tags=["gateway"])
async def query(
    payload: QueryRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> QueryResponse:
    return await container.queries.execute(principal, payload)


@router.get("/audit/{request_id}", response_model=list[AuditEvent], tags=["audit"])
async def audit_events(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> list[AuditEvent]:
    await _enforce_operational_access(principal, container, required_role="auditor")
    return [event async for event in container.audit.stream(request_id)]


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
        },
    )
    return RecordReceipt(
        request_id=request_id,
        record_id=record.id,
        field_count=len(record.fields),
        highest_classification=highest,
    )
