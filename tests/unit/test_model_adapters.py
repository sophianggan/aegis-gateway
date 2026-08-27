import json
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
        model="approved",
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
