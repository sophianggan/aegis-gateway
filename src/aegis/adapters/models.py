from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import httpx

from aegis.errors import UpstreamModelError


class DeterministicModelProvider:
    """Offline provider that makes development and security tests reproducible."""

    async def complete(self, *, system: str, user: str, request_id: UUID) -> str:
        del system, request_id
        try:
            envelope = json.loads(user)
            records = envelope.get("trusted_context", [])
            question = envelope.get("question", "")
        except (json.JSONDecodeError, AttributeError) as exc:
            raise UpstreamModelError("model input envelope was malformed") from exc

        if not records:
            return "I cannot answer from the records available at your access level."

        facts: list[str] = []
        for record in records:
            fields = record.get("fields", {})
            rendered = ", ".join(f"{key}: {value}" for key, value in sorted(fields.items()))
            if rendered:
                facts.append(f"[{record.get('record_id')}] {rendered}")
        return f"Question: {question}\nAuthorized record summary:\n" + "\n".join(facts)


class OpenAICompatibleModelProvider:
    """Minimal adapter for any isolated chat-completions-compatible endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._model = model
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        )

    async def complete(self, *, system: str, user: str, request_id: UUID) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            response = await self._client.post(
                "/chat/completions",
                json=payload,
                headers={"Idempotency-Key": str(request_id)},
            )
            response.raise_for_status()
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("empty model response")
            return content
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise UpstreamModelError("isolated model endpoint failed") from exc

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

