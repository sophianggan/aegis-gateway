import json
import math

import httpx
import pytest

from aegis_sdk import AegisClient, AegisClientError, ClassifiedValue, RecordInput


@pytest.mark.parametrize(
    "base_url",
    [
        "gateway.internal",
        "ftp://gateway.internal",
        "https://user:secret@gateway.internal",
        "https://gateway.internal/prefix",
        "https://gateway.internal?tenant=one",
        "https://gateway.internal#api",
    ],
)
def test_sdk_rejects_unsafe_base_urls(base_url: str) -> None:
    with pytest.raises(ValueError, match=r"HTTP\(S\) origin"):
        AegisClient(base_url, "token")


@pytest.mark.parametrize("timeout", [0, -1, 301, math.nan, math.inf, True, "30"])
def test_sdk_rejects_invalid_timeouts(timeout: float) -> None:
    with pytest.raises(ValueError, match="between 0 and 300"):
        AegisClient("https://gateway.internal", "token", timeout=timeout)


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


async def test_sdk_rejects_non_string_token_provider_result() -> None:
    async def token_provider() -> object:
        return None

    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid credentials must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        token_provider,  # type: ignore[arg-type]
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(AegisClientError, match="must return a string"):
            await client.query("status")


@pytest.mark.parametrize("question", ["", "   ", "\r\n\t"])
async def test_sdk_rejects_blank_questions_before_request(question: str) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("blank questions must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="non-blank"):
            await client.query(question)


@pytest.mark.parametrize("purpose", ["", "   ", "x" * 201])
async def test_sdk_rejects_invalid_query_purpose_before_request(purpose: str) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid purposes must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="purpose must contain between 1 and 200"):
            await client.query("status", purpose=purpose)


async def test_sdk_trims_query_purpose_before_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["purpose"] == "incident response"
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
        "token",
        transport=httpx.MockTransport(handler),
    ) as client:
        await client.query("status", purpose="  incident response  ")


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        ({f"key-{index}": "value" for index in range(21)}, "at most 20"),
        ({"   ": "value"}, "metadata keys"),
        ({"x" * 65: "value"}, "metadata keys"),
        ({"key": "x" * 257}, "metadata values"),
        ({" Region ": "east", "region": "west"}, "unique after normalization"),
        ({"key": 1}, "must be strings"),
    ],
)
async def test_sdk_rejects_invalid_query_metadata_before_request(
    metadata: dict[str, str], message: str
) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid metadata must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match=message):
            await client.query("status", metadata=metadata)


async def test_sdk_normalizes_query_metadata_before_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["metadata"] == {"region": "east"}
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
        "token",
        transport=httpx.MockTransport(handler),
    ) as client:
        await client.query("status", metadata={" Region ": " east "})


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


@pytest.mark.parametrize("payload", [{"valid": "false"}, {"valid": 1}, {}])
async def test_sdk_rejects_invalid_audit_verification(payload: dict[str, object]) -> None:
    request_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)),
    ) as client:
        with pytest.raises(AegisClientError, match="invalid response"):
            await client.verify_audit(request_id)


async def test_bulk_ingestion_validates_concurrency_before_request() -> None:
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match="between 1 and 32"):
            await client.create_records([], concurrency=0)


@pytest.mark.parametrize("concurrency", [True, 1.5, "4"])
async def test_bulk_ingestion_rejects_non_integer_concurrency(concurrency: int) -> None:
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match="between 1 and 32"):
            await client.create_records([], concurrency=concurrency)


async def test_bulk_ingestion_rejects_duplicate_records_before_request() -> None:
    record = RecordInput(source="work-orders", fields={"status": ClassifiedValue(value="open")})

    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("duplicate records must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="duplicate identifiers"):
            await client.create_records([record, record])


async def test_bulk_ingestion_rejects_invalid_record_types_before_request() -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid records must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="RecordInput instances"):
            await client.create_records(["not-a-record"])  # type: ignore[list-item]


async def test_audit_iterator_rejects_invalid_page_size_before_request() -> None:
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match="between 1 and 200"):
            await anext(client.iter_audit_events("request-id", page_size=0))


@pytest.mark.parametrize(
    ("parameter", "value", "message"),
    [
        ("after_sequence", True, "integer at least -1"),
        ("after_sequence", 1.5, "integer at least -1"),
        ("limit", True, "between 1 and 200"),
        ("limit", 1.5, "between 1 and 200"),
    ],
)
async def test_sdk_rejects_non_integer_audit_pagination(
    parameter: str, value: object, message: str
) -> None:
    arguments = {parameter: value}
    async with AegisClient("https://gateway.internal", "token") as client:
        with pytest.raises(ValueError, match=message):
            await client.list_audit_events(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                **arguments,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize("next_sequence", [None, -1, 0])
async def test_audit_iterator_rejects_non_progressing_cursor(
    next_sequence: int | None,
) -> None:
    request_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    response = httpx.Response(
        200,
        json={"events": [], "next_sequence": next_sequence, "has_more": True},
    )
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: response),
    ) as client:
        with pytest.raises(AegisClientError, match="invalid audit page"):
            await anext(client.iter_audit_events(request_id))


def audit_event_payload(*, request_id: str, sequence: int) -> dict[str, object]:
    return {
        "id": f"00000000-0000-4000-8000-{sequence + 1:012d}",
        "request_id": request_id,
        "sequence": sequence,
        "occurred_at": "2026-09-14T12:00:00Z",
        "actor": "auditor",
        "action": "request.complete",
        "decision": "allow",
        "resource_ids": [],
        "details": {},
        "previous_hash": "",
        "event_hash": "0" * 64,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "events": [
                audit_event_payload(
                    request_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", sequence=0
                )
            ],
            "next_sequence": None,
            "has_more": False,
        },
        {
            "events": [
                audit_event_payload(
                    request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sequence=1
                )
            ],
            "next_sequence": None,
            "has_more": False,
        },
        {
            "events": [
                audit_event_payload(
                    request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sequence=0
                )
            ],
            "next_sequence": 0,
            "has_more": False,
        },
    ],
)
async def test_sdk_rejects_inconsistent_audit_pages(payload: dict[str, object]) -> None:
    request_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)),
    ) as client:
        with pytest.raises(AegisClientError, match="invalid audit page"):
            await client.list_audit_events(request_id)


async def test_sdk_rejects_negative_audit_event_sequence() -> None:
    request_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    payload = {
        "events": [audit_event_payload(request_id=request_id, sequence=-1)],
        "next_sequence": None,
        "has_more": False,
    }
    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)),
    ) as client:
        with pytest.raises(AegisClientError, match="invalid response"):
            await client.list_audit_events(request_id)


@pytest.mark.parametrize("resource_id", ["not-a-uuid", "../records", ""])
async def test_sdk_rejects_invalid_path_resource_ids(resource_id: str) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid resource IDs must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="record_id must be a valid UUID"):
            await client.delete_record(resource_id)


async def test_sdk_rejects_invalid_body_resource_ids_before_request() -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid resource IDs must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="record_id must be a valid UUID"):
            await client.query("status", record_ids=["not-a-uuid"])


async def test_sdk_rejects_duplicate_body_resource_ids_before_request() -> None:
    record_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("duplicate resource IDs must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match="must not contain duplicates"):
            await client.preview_policy([record_id, record_id])


@pytest.mark.parametrize(
    ("operation", "record_ids", "expected"),
    [
        ("query", [f"00000000-0000-4000-8000-{index:012d}" for index in range(101)], "0 and 100"),
        ("preview", [], "1 and 100"),
    ],
)
async def test_sdk_enforces_record_selection_limits_before_request(
    operation: str, record_ids: list[str], expected: str
) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid record selections must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match=expected):
            if operation == "query":
                await client.query("status", record_ids=record_ids)
            else:
                await client.preview_policy(record_ids)


@pytest.mark.parametrize(
    ("token_id", "reason_code", "message"),
    [
        ("   ", "administrative", "token_id"),
        ("token-1", "bad reason", "reason_code"),
        ("token-1", "x" * 51, "reason_code"),
    ],
)
async def test_sdk_rejects_invalid_revocation_inputs_before_request(
    token_id: str, reason_code: str, message: str
) -> None:
    def unexpected_request(_: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid revocation input must fail before transport")

    async with AegisClient(
        "https://gateway.internal",
        "token",
        transport=httpx.MockTransport(unexpected_request),
    ) as client:
        with pytest.raises(ValueError, match=message):
            await client.revoke_token(token_id, reason_code=reason_code)
