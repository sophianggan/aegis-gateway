from __future__ import annotations

from dataclasses import dataclass

from aegis.adapters.memory import (
    InMemoryAuditRepository,
    InMemoryRecordRepository,
    InMemoryRevocationStore,
)
from aegis.adapters.models import DeterministicModelProvider, OpenAICompatibleModelProvider
from aegis.config import Settings
from aegis.ports import AuditRepository, ModelProvider, RecordRepository, RevocationStore
from aegis.security.identity import TokenAuthenticator
from aegis.security.input_guard import InputGuard
from aegis.security.output_guard import OutputGuard
from aegis.services.audit import AuditTrail
from aegis.services.policy import PolicyEngine
from aegis.services.query import QueryService


@dataclass
class Container:
    settings: Settings
    authenticator: TokenAuthenticator
    records: RecordRepository
    audit_repository: AuditRepository
    revocations: RevocationStore
    model: ModelProvider
    audit: AuditTrail
    queries: QueryService

    @classmethod
    def build(cls, settings: Settings) -> Container:
        records = InMemoryRecordRepository()
        audit_repository = InMemoryAuditRepository()
        revocations = InMemoryRevocationStore()
        if settings.model_provider == "openai-compatible":
            model: ModelProvider = OpenAICompatibleModelProvider(
                base_url=settings.model_base_url,
                api_key=settings.model_api_key.get_secret_value(),
                model=settings.model_name,
                timeout_seconds=settings.request_timeout_seconds,
            )
        else:
            model = DeterministicModelProvider()
        audit = AuditTrail(audit_repository, settings.audit_hmac_key.get_secret_value())
        queries = QueryService(
            records=records,
            model=model,
            revocations=revocations,
            policy=PolicyEngine(),
            input_guard=InputGuard(),
            output_guard=OutputGuard(),
            audit=audit,
            max_records=settings.max_context_records,
        )
        return cls(
            settings=settings,
            authenticator=TokenAuthenticator(settings),
            records=records,
            audit_repository=audit_repository,
            revocations=revocations,
            model=model,
            audit=audit,
            queries=queries,
        )

