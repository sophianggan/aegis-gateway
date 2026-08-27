from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aegis.api.dependencies import get_container, get_principal
from aegis.container import Container
from aegis.domain.models import AuditEvent, Principal, QueryRequest, QueryResponse

router = APIRouter(prefix="/v1")


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
    if "auditor" not in principal.roles:
        from aegis.errors import AuthorizationError

        raise AuthorizationError("auditor role is required")
    return [event async for event in container.audit.stream(request_id)]


@router.get("/audit/{request_id}/verify", tags=["audit"])
async def verify_audit_chain(
    request_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    container: Annotated[Container, Depends(get_container)],
) -> dict[str, bool]:
    if "auditor" not in principal.roles:
        from aegis.errors import AuthorizationError

        raise AuthorizationError("auditor role is required")
    return {"valid": await container.audit.verify(request_id)}
