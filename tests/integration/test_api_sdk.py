from __future__ import annotations

from uuid import UUID

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from aegis.config import Settings
from aegis.container import Container
from aegis.demo_data import DEMO_RECORDS
from aegis.domain.models import Classification
from aegis.main import create_app
from aegis_sdk import AegisClient, AegisClientError


def runtime_settings() -> Settings:
    return Settings(
        environment="test",
        persistence="memory",
        jwt_secret=SecretStr("api-test-jwt-secret-that-is-long-enough"),
        audit_hmac_key=SecretStr("api-test-audit-secret-that-is-long"),
    )


async def configured_app() -> tuple[FastAPI, Container, str]:
    settings = runtime_settings()
    container = Container.build(settings)
    for record in DEMO_RECORDS:
        await container.records.put(record)
    token = container.authenticator.issue_development_token(
        subject="sdk-user",
        clearance=Classification.CONFIDENTIAL,
        compartments={"operations"},
        roles={"auditor"},
    )
    return create_app(settings=settings, container=container), container, token


async def test_http_api_returns_only_authorized_fields() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "query": "Which inspection is due?",
                "record_ids": [str(DEMO_RECORDS[0].id)],
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["filtered_field_count"] == 1
    assert "NORTH-7391" not in body["answer"]
    assert body["citations"][0]["disclosed_fields"] == ["asset", "site", "status"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_api_uses_stable_error_envelope() -> None:
    app, _, _ = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            json={"query": "Summarize", "record_ids": []},
        )

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "authentication_failed",
            "message": "missing bearer token",
            "details": {},
        }
    }


async def test_auditor_can_verify_completed_request_chain() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        query = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "Summarize", "record_ids": [str(DEMO_RECORDS[0].id)]},
        )
        request_id = UUID(query.json()["request_id"])
        verification = await client.get(
            f"/v1/audit/{request_id}/verify",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert verification.status_code == 200
    assert verification.json() == {"valid": True}


async def test_async_sdk_wraps_api_and_typed_response() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query(
            "Summarize maintenance",
            record_ids=[DEMO_RECORDS[0].id],
            purpose="operations review",
        )

    assert result.answer.startswith("Question: Summarize maintenance")
    assert result.citations[0].record_id == DEMO_RECORDS[0].id


async def test_sdk_surfaces_gateway_error_code() -> None:
    app, _, _ = await configured_app()
    transport = httpx.ASGITransport(app=app)
    try:
        async with AegisClient("http://test", "invalid-token", transport=transport) as client:
            await client.query("Summarize")
    except AegisClientError as exc:
        assert exc.code == "authentication_failed"
        assert exc.status_code == 401
    else:
        raise AssertionError("SDK should surface authentication failures")


async def test_rate_limit_returns_retry_after_header() -> None:
    settings = Settings(
        environment="test",
        persistence="memory",
        jwt_secret=SecretStr("rate-test-jwt-secret-that-is-long-enough"),
        audit_hmac_key=SecretStr("rate-test-audit-secret-that-is-long"),
        rate_limit_requests_per_minute=1,
        rate_limit_burst=1,
    )
    container = Container.build(settings)
    token = container.authenticator.issue_development_token(
        subject="limited-user", clearance=Classification.INTERNAL
    )
    app = create_app(settings=settings, container=container)
    transport = httpx.ASGITransport(app=app)
    payload = {"query": "status", "record_ids": []}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/v1/query", headers={"Authorization": f"Bearer {token}"}, json=payload
        )
        limited = await client.post(
            "/v1/query", headers={"Authorization": f"Bearer {token}"}, json=payload
        )

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    assert limited.json()["error"]["code"] == "rate_limit_exceeded"


async def test_data_admin_can_ingest_classified_record_then_query_safe_fields() -> None:
    app, container, _ = await configured_app()
    admin_token = container.authenticator.issue_development_token(
        subject="data-steward",
        clearance=Classification.INTERNAL,
        roles={"data-admin"},
    )
    record_id = "33333333-3333-4333-8333-333333333333"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/v1/records",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "id": record_id,
                "source": "controlled-import",
                "fields": {
                    "summary": {"value": "inspection complete", "classification": "INTERNAL"},
                    "local_key": {
                        "value": "LOCAL-KEY-9912",
                        "classification": "RESTRICTED",
                        "exportable": False,
                    },
                },
            },
        )
        queried = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"query": "What is the status?", "record_ids": [record_id]},
        )

    assert created.status_code == 201
    assert created.json()["highest_classification"] == 30
    assert queried.status_code == 200
    assert "inspection complete" in queried.json()["answer"]
    assert "LOCAL-KEY-9912" not in queried.json()["answer"]


async def test_record_ingestion_requires_data_admin_role() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/records",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source": "controlled-import",
                "fields": {"summary": {"value": "safe", "classification": "PUBLIC"}},
            },
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_denied"
