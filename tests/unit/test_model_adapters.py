import json
import math
from uuid import uuid4

import httpx
import pytest

from aegis.adapters.models import DeterministicModelProvider, OpenAICompatibleModelProvider
from aegis.errors import UpstreamModelError


async def test_deterministic_provider_handles_empty_context() -> None:
    provider = DeterministicModelProvider()
    answer = await provider.complete(
        system="boundary",
        user=json.dumps({"question": "What happened?", "trusted_context": []}),
        request_id=uuid4(),
    )
    assert "cannot answer" in answer


async def test_deterministic_provider_rejects_malformed_envelope() -> None:
    with pytest.raises(UpstreamModelError):
        await DeterministicModelProvider().complete(
            system="boundary", user="not-json", request_id=uuid4()
        )


async def test_remote_provider_parses_compatible_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Idempotency-Key"]
        body = json.loads(request.content)
        assert body["temperature"] == 0
        assert body["model"] == "approved"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "bounded answer"}}]},
        )

    client = httpx.AsyncClient(
        base_url="https://model.internal", transport=httpx.MockTransport(handler)
    )
    provider = OpenAICompatibleModelProvider(
        base_url="https://ignored.internal",
        api_key="",
        model="  approved  ",
        timeout_seconds=5,
        client=client,
    )
    answer = await provider.complete(system="boundary", user="payload", request_id=uuid4())
    await provider.close()
    await client.aclose()
    assert answer == "bounded answer"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, json={"error": "unavailable"}),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": ""}}]}),
    ],
)
async def test_remote_provider_fails_closed_on_upstream_errors(response: httpx.Response) -> None:
    client = httpx.AsyncClient(
        base_url="https://model.internal",
        transport=httpx.MockTransport(lambda _: response),
    )
    provider = OpenAICompatibleModelProvider(
        base_url="https://ignored.internal",
        api_key="key",
        model="approved",
        timeout_seconds=5,
        client=client,
    )
    with pytest.raises(UpstreamModelError):
        await provider.complete(system="boundary", user="payload", request_id=uuid4())
    await client.aclose()


async def test_remote_provider_closes_owned_client() -> None:
    provider = OpenAICompatibleModelProvider(
        base_url="https://model.internal",
        api_key="key",
        model="approved",
        timeout_seconds=5,
    )
    await provider.close()


@pytest.mark.parametrize(
    "base_url",
    [
        "model.internal",
        "ftp://model.internal/v1",
        "https://user:secret@model.internal/v1",
        "https://model.internal/v1?key=secret",
        "https://model.internal/v1#chat",
    ],
)
def test_remote_provider_rejects_unsafe_base_url(base_url: str) -> None:
    with pytest.raises(ValueError, match=r"HTTP\(S\)"):
        OpenAICompatibleModelProvider(
            base_url=base_url,
            api_key="key",
            model="approved",
            timeout_seconds=5,
        )


@pytest.mark.parametrize("model", ["", "   ", "x" * 201])
def test_remote_provider_rejects_invalid_model_name(model: str) -> None:
    with pytest.raises(ValueError, match="model name"):
        OpenAICompatibleModelProvider(
            base_url="https://model.internal/v1",
            api_key="key",
            model=model,
            timeout_seconds=5,
        )


@pytest.mark.parametrize("timeout", [0, -1, 301, math.nan, math.inf, True, "30"])
def test_remote_provider_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="model timeout"):
        OpenAICompatibleModelProvider(
            base_url="https://model.internal/v1",
            api_key="key",
            model="approved",
            timeout_seconds=timeout,
        )


def test_remote_provider_rejects_non_string_api_key() -> None:
    with pytest.raises(ValueError, match="API key"):
        OpenAICompatibleModelProvider(
            base_url="https://model.internal/v1",
            api_key=None,  # type: ignore[arg-type]
            model="approved",
            timeout_seconds=5,
        )
