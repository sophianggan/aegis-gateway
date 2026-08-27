import asyncio

import httpx
from pydantic import SecretStr

from aegis.config import Settings
from aegis.container import Container
from aegis.demo_data import DEMO_RECORDS
from aegis.domain.models import Classification
from aegis.main import create_app
from aegis_sdk import AegisClient


async def demonstrate() -> None:
    settings = Settings(
        environment="test",
        persistence="memory",
        jwt_secret=SecretStr("quickstart-jwt-key-change-for-real-use"),
        audit_hmac_key=SecretStr("quickstart-audit-key-change-for-real-use"),
    )
    container = Container.build(settings)
    for record in DEMO_RECORDS:
        await container.records.put(record)

    token = container.authenticator.issue_development_token(
        subject="quickstart-analyst",
        clearance=Classification.CONFIDENTIAL,
        compartments={"operations"},
        roles={"auditor"},
    )
    app = create_app(settings=settings, container=container)
    transport = httpx.ASGITransport(app=app)
    async with AegisClient("http://aegis.local", token, transport=transport) as client:
        result = await client.query(
            "Which inspection is due and where?",
            record_ids=[DEMO_RECORDS[0].id],
            purpose="maintenance planning",
        )
        chain_is_valid = await client.verify_audit(result.request_id)

    print(result.answer)
    print(f"\nFiltered fields: {result.filtered_field_count}")
    print(f"Disclosed fields: {result.citations[0].disclosed_fields}")
    print(f"Audit chain valid: {chain_is_valid}")


if __name__ == "__main__":
    asyncio.run(demonstrate())
