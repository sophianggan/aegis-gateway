import httpx
import pytest

from aegis_sdk import AegisClient, AegisClientError


@pytest.mark.parametrize(
    "base_url",
    [
        "gateway.internal",
        "ftp://gateway.internal",
        "https://user:secret@gateway.internal",
        "https://gateway.internal?tenant=one",
        "https://gateway.internal#api",
    ],
)
def test_sdk_rejects_unsafe_base_urls(base_url: str) -> None:
    with pytest.raises(ValueError, match=r"HTTP\(S\) origin"):
        AegisClient(base_url, "token")


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


@pytest.mark.parametrize("token", ["", "   "])
async def test_sdk_rejects_blank_static_token_before_request(token: str) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("blank credentials must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        token,
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(AegisClientError, match="must not be blank"):
            await client.query("status")


async def test_sdk_rejects_blank_token_provider_result() -> None:
    async def token_provider() -> str:
        return " "

    async with AegisClient("https://gateway.internal", token_provider) as client:
        with pytest.raises(AegisClientError, match="must not be blank"):
            await client.query("status")


@pytest.mark.parametrize("correlation_id", ["", "bad\nheader", "x" * 129])
async def test_sdk_rejects_unsafe_correlation_id(correlation_id: str) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("unsafe correlation IDs must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(AegisClientError, match="header-safe"):
            await client.query("status", correlation_id=correlation_id)


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


async def test_sdk_wraps_invalid_typed_gateway_response() -> None:
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"answer": "ok"})),
    ) as client:
        with pytest.raises(AegisClientError, match="invalid response") as captured:
            await client.query("status")

    assert captured.value.code == "invalid_response"
    assert captured.value.status_code == 0


async def test_bulk_ingestion_validates_concurrency_before_request() -> None:
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match="between 1 and 32"):
            await client.create_records([], concurrency=0)


async def test_audit_iterator_rejects_invalid_page_size_before_request() -> None:
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match="between 1 and 200"):
            await anext(client.iter_audit_events("request-id", page_size=0))
