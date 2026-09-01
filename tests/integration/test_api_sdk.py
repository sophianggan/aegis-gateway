from __future__ import annotations

from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from aegis.config import Settings
from aegis.container import Container
from aegis.demo_data import DEMO_RECORDS
from aegis.domain.models import Classification
from aegis.main import create_app
from aegis_sdk import (
    AegisClient,
    AegisClientError,
    ClassifiedValue,
    RecordInput,
)
from aegis_sdk import Classification as SdkClassification


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


async def test_query_metadata_is_bounded_and_normalized() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        accepted = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "status", "metadata": {" Trace-ID ": " 123 "}},
        )
        rejected = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "status", "metadata": {"trace-id": "x" * 257}},
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 422


async def test_query_rejects_duplicate_record_identifiers() -> None:
    app, _, token = await configured_app()
    record_id = str(DEMO_RECORDS[0].id)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "status", "record_ids": [record_id, record_id]},
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == "record_ids"


async def test_query_fails_explicitly_above_configured_record_limit() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "status", "record_ids": [str(uuid4()) for _ in range(21)]},
        )

    assert response.status_code == 413
    assert response.json()["error"] == {
        "code": "request_limit_exceeded",
        "message": "query exceeds the configured record limit",
        "details": {"max_records": 20},
    }


async def test_strict_query_fails_before_model_when_a_record_is_missing() -> None:
    app, _, token = await configured_app()
    missing_id = "99999999-9999-4999-8999-999999999999"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "query": "Summarize",
                "record_ids": [str(DEMO_RECORDS[0].id), missing_id],
                "require_all_records": True,
            },
        )

    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "resource_not_found",
        "message": "one or more requested records were not found",
        "details": {"missing_record_ids": [missing_id]},
    }


async def test_non_strict_query_returns_missing_record_provenance() -> None:
    app, _, token = await configured_app()
    missing_id = UUID("99999999-9999-4999-8999-999999999999")
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query("Summarize", record_ids=[DEMO_RECORDS[0].id, missing_id])

    assert result.missing_record_ids == [missing_id]
    assert result.citations[0].record_id == DEMO_RECORDS[0].id


async def test_readiness_probes_persistence_dependency() -> None:
    app, container, _ = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ready = await client.get("/v1/health/ready")

        async def unavailable() -> bool:
            return False

        container.records.healthcheck = unavailable  # type: ignore[method-assign]
        degraded = await client.get("/v1/health/ready")

    assert ready.status_code == 200
    assert ready.json() == {"status": "ready", "checks": {"persistence": "ok"}}
    assert degraded.status_code == 503
    assert degraded.json() == {
        "status": "degraded",
        "checks": {"persistence": "unavailable"},
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


async def test_sdk_paginates_audit_events_with_stable_sequence_cursor() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query("Summarize", record_ids=[DEMO_RECORDS[0].id])
        first = await client.list_audit_events(result.request_id, limit=2)
        second = await client.list_audit_events(
            result.request_id, after_sequence=first.next_sequence or 0, limit=10
        )

    assert [event.sequence for event in first.events] == [0, 1]
    assert first.has_more is True
    assert first.next_sequence == 1
    assert [event.sequence for event in second.events] == [2, 3, 4, 5]
    assert second.has_more is False
    assert second.next_sequence is None


async def test_sdk_iterates_complete_audit_history_across_pages() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query("Summarize", record_ids=[DEMO_RECORDS[0].id])
        events = [
            event
            async for event in client.iter_audit_events(result.request_id, page_size=2)
        ]

    assert [event.sequence for event in events] == list(range(6))
    assert events[-1].action == "request.complete"


async def test_sdk_creates_compact_signed_audit_checkpoint() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query("Summarize", record_ids=[DEMO_RECORDS[0].id])
        checkpoint = await client.create_audit_checkpoint(result.request_id)

    assert checkpoint.request_id == result.request_id
    assert checkpoint.event_count == 6
    assert len(checkpoint.chain_head) == 64
    assert len(checkpoint.signature) == 64


async def test_async_sdk_wraps_api_and_typed_response() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        result = await client.query(
            "Summarize maintenance",
            record_ids=[DEMO_RECORDS[0].id],
            purpose="operations review",
        )
        bundle = await client.export_audit(result.request_id)

    assert result.answer.startswith("Question: Summarize maintenance")
    assert result.citations[0].record_id == DEMO_RECORDS[0].id
    assert bundle.request_id == result.request_id
    assert bundle.event_count == 6
    assert len(bundle.bundle_signature) == 64


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


async def test_query_rejects_unapproved_data_use_purpose_before_retrieval() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "Summarize", "purpose": "unapproved exploration"},
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_denied"
    assert response.json()["error"]["details"]["purpose"] == "unapproved-exploration"


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
    assert created.json()["integrity_algorithm"] == "HMAC-SHA256"
    assert len(created.json()["integrity_digest"]) == 64
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


async def test_record_ingestion_rejects_unsafe_field_names() -> None:
    app, container, _ = await configured_app()
    token = container.authenticator.issue_development_token(
        subject="data-steward",
        clearance=Classification.INTERNAL,
        roles={"data-admin"},
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/records",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source": "controlled-import",
                "fields": {"../secret": {"value": "unsafe", "classification": "PUBLIC"}},
            },
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == "fields"


async def test_record_ingestion_audits_and_rejects_oversized_payload() -> None:
    settings = runtime_settings().model_copy(update={"max_record_bytes": 1_024})
    container = Container.build(settings)
    token = container.authenticator.issue_development_token(
        subject="data-steward",
        clearance=Classification.INTERNAL,
        roles={"data-admin"},
    )
    app = create_app(settings=settings, container=container)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/records",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source": "large-import",
                "fields": {"content": {"value": "x" * 2_000, "classification": "PUBLIC"}},
            },
        )

    assert response.status_code == 413
    assert response.json()["error"]["details"] == {"max_record_bytes": 1_024}
    event = next(iter(container.audit_repository._events.values()))[0]  # type: ignore[attr-defined]
    assert event.action == "record.upsert"
    assert event.decision == "deny"


async def test_data_admin_retires_record_but_preserves_audit_evidence() -> None:
    app, container, _ = await configured_app()
    token = container.authenticator.issue_development_token(
        subject="retention-admin",
        clearance=Classification.RESTRICTED,
        roles={"data-admin", "auditor"},
    )
    record = RecordInput(
        source="retention-test",
        fields={
            "summary": ClassifiedValue(value="expired", classification=SdkClassification.PUBLIC)
        },
    )
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        created = await client.create_record(record)
        retired = await client.delete_record(created.record_id)
        result = await client.query("Summarize", record_ids=[created.record_id])
        evidence = await client.export_audit(retired.request_id)

    assert retired.deleted is True
    assert result.missing_record_ids == [created.record_id]
    assert evidence.events[0].action == "record.delete"


async def test_record_retirement_is_idempotent_and_audited() -> None:
    app, container, _ = await configured_app()
    token = container.authenticator.issue_development_token(
        subject="retention-admin",
        clearance=Classification.RESTRICTED,
        roles={"data-admin"},
    )
    missing = UUID("88888888-8888-4888-8888-888888888888")
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        receipt = await client.delete_record(missing)
    assert receipt.deleted is False
    assert receipt.record_id == missing


async def test_security_admin_revokes_token_through_sdk_and_audits_action() -> None:
    app, container, _ = await configured_app()
    admin_token = container.authenticator.issue_development_token(
        subject="security-admin",
        clearance=Classification.RESTRICTED,
        roles={"security-admin", "auditor"},
    )
    target_token = container.authenticator.issue_development_token(
        subject="target-user", clearance=Classification.INTERNAL
    )
    target_id = container.authenticator.authenticate(f"Bearer {target_token}").token_id
    assert target_id is not None
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", admin_token, transport=transport) as client:
        receipt = await client.revoke_token(target_id, reason_code="suspected-compromise")
        bundle = await client.export_audit(receipt.request_id)
    async with AegisClient("http://test", target_token, transport=transport) as target:
        try:
            await target.query("status")
        except AegisClientError as exc:
            assert exc.code == "authentication_failed"
        else:
            raise AssertionError("revoked credential should be denied")

    assert receipt.revoked is True
    assert bundle.events[0].action == "token.revoke"
    assert target_id not in bundle.model_dump_json()


async def test_metrics_use_route_templates_and_never_capture_payloads() -> None:
    app, _, token = await configured_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/v1/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "unique-private-query-marker", "record_ids": []},
        )
        response = await client.get("/metrics")

    assert response.status_code == 200
    assert 'route="/v1/query"' in response.text
    assert "unique-private-query-marker" not in response.text


async def test_sdk_ingests_multiple_typed_records_in_order() -> None:
    app, container, _ = await configured_app()
    token = container.authenticator.issue_development_token(
        subject="sdk-steward",
        clearance=Classification.CONFIDENTIAL,
        roles={"data-admin"},
    )
    records = [
        RecordInput(
            source=f"sdk-import-{index}",
            fields={
                "summary": ClassifiedValue(
                    value=f"record-{index}",
                    classification=SdkClassification.INTERNAL,
                ),
                "control": ClassifiedValue(
                    value=f"CONTROL-{index}",
                    classification=SdkClassification.RESTRICTED,
                    exportable=False,
                ),
            },
        )
        for index in range(3)
    ]
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        receipts = await client.create_records(records, concurrency=2)

    assert [receipt.record_id for receipt in receipts] == [record.id for record in records]
    assert all(receipt.field_count == 2 for receipt in receipts)
    assert all(len(receipt.integrity_digest) == 64 for receipt in receipts)
    assert all(
        receipt.highest_classification == SdkClassification.RESTRICTED for receipt in receipts
    )


async def test_policy_preview_explains_decisions_without_values() -> None:
    app, container, _ = await configured_app()
    token = container.authenticator.issue_development_token(
        subject="policy-reviewer",
        clearance=Classification.CONFIDENTIAL,
        compartments={"operations"},
        roles={"policy-reviewer", "auditor"},
    )
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://test", token, transport=transport) as client:
        preview = await client.preview_policy([DEMO_RECORDS[0].id])
        bundle = await client.export_audit(preview.request_id)

    assert preview.records[0].allowed_fields == ["asset", "site", "status"]
    assert preview.records[0].filtered_fields == ["access_code"]
    assert preview.records[0].reasons == ["non_exportable"]
    assert "OPS-7391-Z" not in preview.model_dump_json()
    assert bundle.events[0].action == "policy.preview"
