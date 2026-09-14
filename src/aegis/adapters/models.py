from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import urlsplit
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
                "model base URL must use HTTP(S) without credentials, query, or fragment"
            )
        if not isinstance(model, str) or not model.strip() or len(model.strip()) > 200:
            raise ValueError("model name must contain between 1 and 200 characters")
        if not isinstance(api_key, str):
            raise ValueError("model API key must be a string")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ValueError("model timeout must be finite and between 0 and 300 seconds")
        self._model = model.strip()
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
