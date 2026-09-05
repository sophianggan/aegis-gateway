from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from typing import Any, TypeVar
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, ValidationError

from aegis_sdk.models import (
    AuditBundle,
    AuditCheckpoint,
    AuditEvent,
    AuditPage,
    AuditVerification,
    PolicyPreview,
    QueryResult,
    RecordDeletionReceipt,
    RecordInput,
    RecordReceipt,
    TokenRevocationReceipt,
)

TokenProvider = Callable[[], str | Awaitable[str]]
_CORRELATION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
ResponseModel = TypeVar("ResponseModel", bound=BaseModel)


class AegisClientError(Exception):
    def __init__(self, message: str, *, code: str = "client_error", status_code: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _validate_response(
    model: type[ResponseModel], payload: dict[str, Any]
) -> ResponseModel:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise AegisClientError(
            "gateway returned an invalid response", code="invalid_response"
        ) from exc


def _format_resource_id(value: UUID | str, *, name: str) -> str:
    try:
        return str(UUID(str(value)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a valid UUID") from exc


def _format_resource_ids(values: Sequence[UUID | str], *, name: str) -> list[str]:
    formatted = [_format_resource_id(value, name=name) for value in values]
    if len(formatted) != len(set(formatted)):
        raise ValueError(f"{name}s must not contain duplicates")
    return formatted


class AegisClient:
    """Small async SDK that keeps authentication and error handling consistent."""

    def __init__(
        self,
        base_url: str,
        token: str | TokenProvider,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError(
                "base_url must be an HTTP(S) origin without credentials, query, or fragment"
            )
        self._token = token
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": "aegis-python/0.1.0"},
        )

    async def __aenter__(self) -> AegisClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def query(
        self,
        question: str,
        *,
        record_ids: Sequence[UUID | str] = (),
        purpose: str = "analysis",
        metadata: dict[str, str] | None = None,
        correlation_id: str | None = None,
        require_all_records: bool = False,
    ) -> QueryResult:
        formatted_record_ids = _format_resource_ids(record_ids, name="record_id")
        response = await self._request(
            "POST",
            "/v1/query",
            json={
                "query": question,
                "record_ids": formatted_record_ids,
                "purpose": purpose,
                "metadata": metadata or {},
                "require_all_records": require_all_records,
            },
            correlation_id=correlation_id,
        )
        return _validate_response(QueryResult, response)

    async def verify_audit(self, request_id: UUID | str) -> bool:
        request_id = _format_resource_id(request_id, name="request_id")
        response = await self._request("GET", f"/v1/audit/{request_id}/verify")
        return _validate_response(AuditVerification, response).valid

    async def preview_policy(self, record_ids: Sequence[UUID | str]) -> PolicyPreview:
        formatted_record_ids = _format_resource_ids(record_ids, name="record_id")
        response = await self._request(
            "POST",
            "/v1/policy/preview",
            json={"record_ids": formatted_record_ids},
        )
        return _validate_response(PolicyPreview, response)

    async def export_audit(self, request_id: UUID | str) -> AuditBundle:
        request_id = _format_resource_id(request_id, name="request_id")
        response = await self._request("GET", f"/v1/audit/{request_id}/export")
        return _validate_response(AuditBundle, response)

    async def create_audit_checkpoint(self, request_id: UUID | str) -> AuditCheckpoint:
        request_id = _format_resource_id(request_id, name="request_id")
        response = await self._request("GET", f"/v1/audit/{request_id}/checkpoint")
        return _validate_response(AuditCheckpoint, response)

    async def list_audit_events(
        self, request_id: UUID | str, *, after_sequence: int = -1, limit: int = 50
    ) -> AuditPage:
        if after_sequence < -1:
            raise ValueError("after_sequence must be at least -1")
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        request_id = _format_resource_id(request_id, name="request_id")
        response = await self._request(
            "GET",
            f"/v1/audit/{request_id}/events?after_sequence={after_sequence}&limit={limit}",
        )
        return _validate_response(AuditPage, response)

    async def iter_audit_events(
        self, request_id: UUID | str, *, page_size: int = 50
    ) -> AsyncIterator[AuditEvent]:
        after_sequence = -1
        while True:
            page = await self.list_audit_events(
                request_id,
                after_sequence=after_sequence,
                limit=page_size,
            )
            for event in page.events:
                yield event
            if not page.has_more:
                return
            if (
                page.next_sequence is None
                or page.next_sequence <= after_sequence
                or not page.events
                or page.next_sequence != page.events[-1].sequence
            ):
                raise AegisClientError("gateway returned an invalid audit cursor")
            after_sequence = page.next_sequence

    async def create_record(self, record: RecordInput) -> RecordReceipt:
        response = await self._request(
            "POST",
            "/v1/records",
            json=record.model_dump(mode="json"),
        )
        return _validate_response(RecordReceipt, response)

    async def delete_record(self, record_id: UUID | str) -> RecordDeletionReceipt:
        record_id = _format_resource_id(record_id, name="record_id")
        response = await self._request("DELETE", f"/v1/records/{record_id}")
        return _validate_response(RecordDeletionReceipt, response)

    async def revoke_token(
        self, token_id: str, *, reason_code: str = "administrative"
    ) -> TokenRevocationReceipt:
        response = await self._request(
            "POST",
            "/v1/admin/token-revocations",
            json={"token_id": token_id, "reason_code": reason_code},
        )
        return _validate_response(TokenRevocationReceipt, response)

    async def create_records(
        self,
        records: Sequence[RecordInput],
        *,
        concurrency: int = 4,
    ) -> list[RecordReceipt]:
        if concurrency < 1 or concurrency > 32:
            raise ValueError("concurrency must be between 1 and 32")
        semaphore = asyncio.Semaphore(concurrency)

        async def create(record: RecordInput) -> RecordReceipt:
            async with semaphore:
                return await self.create_record(record)

        return list(await asyncio.gather(*(create(record) for record in records)))

    async def _resolve_token(self) -> str:
        resolved: str | Awaitable[str]
        resolved = self._token if isinstance(self._token, str) else self._token()
        if isinstance(resolved, Awaitable):
            resolved = await resolved
        if not isinstance(resolved, str):
            raise AegisClientError("authentication token provider must return a string")
        normalized = resolved.strip()
        if not normalized:
            raise AegisClientError("authentication token must not be blank")
        return normalized

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if correlation_id is None:
            request_id = str(uuid4())
        elif _CORRELATION_ID_PATTERN.fullmatch(correlation_id):
            request_id = correlation_id
        else:
            raise AegisClientError(
                "correlation_id must contain 1-128 header-safe characters"
            )
        headers = {
            "Authorization": f"Bearer {await self._resolve_token()}",
            "X-Request-ID": request_id,
        }
        try:
            response = await self._client.request(method, path, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise AegisClientError("gateway could not be reached") from exc
        if response.is_error:
            try:
                error = response.json()["error"]
                message = str(error["message"])
                code = str(error["code"])
            except (ValueError, KeyError, TypeError):
                message, code = "gateway request failed", "http_error"
            raise AegisClientError(message, code=code, status_code=response.status_code)
        try:
            payload: dict[str, Any] = response.json()
            return payload
        except (ValueError, TypeError) as exc:
            raise AegisClientError("gateway returned malformed JSON") from exc
