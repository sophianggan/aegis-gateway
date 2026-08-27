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


def test_settings() -> Settings:
    return Settings(
        environment="test",
        persistence="memory",
        jwt_secret=SecretStr("api-test-jwt-secret-that-is-long-enough"),
        audit_hmac_key=SecretStr("api-test-audit-secret-that-is-long"),
    )


async def configured_app() -> tuple[FastAPI, Container, str]:
    settings = test_settings()
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
