import httpx
import pytest

from aegis_sdk import AegisClient, AegisClientError


async def test_sdk_supports_async_token_provider() -> None:
    async def token_provider() -> str:
        return "fresh-token"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer fresh-token"
        return httpx.Response(
            200,
            json={
                "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "answer": "ok",
                "citations": [],
                "filtered_field_count": 0,
                "policy_summary": "passed",
            },
        )

    async with AegisClient(
        "https://gateway.internal",
        token_provider,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.query("status")
    assert result.answer == "ok"


async def test_sdk_converts_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(AegisClientError, match="could not be reached"):
            await client.query("status")


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(500, text="not-json"), "gateway request failed"),
        (httpx.Response(200, text="not-json"), "malformed JSON"),
    ],
)
async def test_sdk_rejects_malformed_gateway_responses(
    response: httpx.Response, expected: str
) -> None:
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: response),
    ) as client:
        with pytest.raises(AegisClientError, match=expected):
            await client.query("status")
