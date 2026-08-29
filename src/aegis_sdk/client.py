from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any
from uuid import UUID, uuid4

import httpx

from aegis_sdk.models import AuditBundle, PolicyPreview, QueryResult, RecordInput, RecordReceipt

TokenProvider = Callable[[], str | Awaitable[str]]


class AegisClientError(Exception):
    def __init__(self, message: str, *, code: str = "client_error", status_code: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


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
    ) -> QueryResult:
        response = await self._request(
            "POST",
            "/v1/query",
            json={
                "query": question,
                "record_ids": [str(item) for item in record_ids],
                "purpose": purpose,
                "metadata": metadata or {},
            },
            correlation_id=correlation_id,
        )
        return QueryResult.model_validate(response)

    async def verify_audit(self, request_id: UUID | str) -> bool:
        response = await self._request("GET", f"/v1/audit/{request_id}/verify")
        return bool(response["valid"])

    async def preview_policy(self, record_ids: Sequence[UUID | str]) -> PolicyPreview:
        response = await self._request(
            "POST",
            "/v1/policy/preview",
            json={"record_ids": [str(item) for item in record_ids]},
        )
        return PolicyPreview.model_validate(response)

    async def export_audit(self, request_id: UUID | str) -> AuditBundle:
        response = await self._request("GET", f"/v1/audit/{request_id}/export")
        return AuditBundle.model_validate(response)

    async def create_record(self, record: RecordInput) -> RecordReceipt:
        response = await self._request(
            "POST",
            "/v1/records",
            json=record.model_dump(mode="json"),
        )
        return RecordReceipt.model_validate(response)

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
        if isinstance(self._token, str):
            return self._token
        token = self._token()
        if isinstance(token, Awaitable):
            token = await token
        return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {await self._resolve_token()}",
            "X-Request-ID": correlation_id or str(uuid4()),
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
