from __future__ import annotations

from dataclasses import dataclass

import asyncpg

from aegis.adapters.memory import (
    InMemoryAuditRepository,
    InMemoryRecordRepository,
    InMemoryRevocationStore,
)
from aegis.adapters.models import DeterministicModelProvider, OpenAICompatibleModelProvider
from aegis.adapters.postgres import (
    PostgresAuditRepository,
    PostgresRecordRepository,
    PostgresRevocationStore,
)
from aegis.config import Settings
from aegis.ports import (
    AuditRepository,
    ModelProvider,
    RateLimiter,
    RecordRepository,
    RevocationStore,
)
from aegis.security.identity import TokenAuthenticator
from aegis.security.input_guard import InputGuard
from aegis.security.output_guard import OutputGuard
from aegis.services.audit import AuditTrail
from aegis.services.context_budget import ContextBudget
from aegis.services.policy import PolicyEngine
from aegis.services.policy_preview import PolicyPreviewService
from aegis.services.purpose import PurposePolicy
from aegis.services.query import QueryService
from aegis.services.rate_limit import InMemoryTokenBucket, PostgresFixedWindowRateLimiter
from aegis.services.record_integrity import RecordIntegrity


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
    rate_limiter: RateLimiter
    policy_previews: PolicyPreviewService
    record_integrity: RecordIntegrity
    pool: asyncpg.Pool | None = None

    @classmethod
    def build(cls, settings: Settings) -> Container:
        records = InMemoryRecordRepository()
        audit_repository = InMemoryAuditRepository()
        revocations = InMemoryRevocationStore()
        model = cls._build_model(settings)
        audit = AuditTrail(audit_repository, settings.audit_hmac_key.get_secret_value())
        rate_limiter = cls._build_rate_limiter(settings)
        policy = PolicyEngine()
        purpose_policy = PurposePolicy(settings.allowed_query_purposes)
        queries = QueryService(
            records=records,
            model=model,
            revocations=revocations,
            policy=policy,
            input_guard=InputGuard(),
            output_guard=OutputGuard(),
            audit=audit,
            rate_limiter=rate_limiter,
            max_records=settings.max_context_records,
            purpose_policy=purpose_policy,
            context_budget=ContextBudget(settings.max_context_bytes),
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
            rate_limiter=rate_limiter,
            policy_previews=PolicyPreviewService(
                records=records,
                policy=policy,
                audit=audit,
                max_records=settings.max_context_records,
            ),
            record_integrity=RecordIntegrity(settings.audit_hmac_key.get_secret_value()),
        )

    @classmethod
    async def build_postgres(cls, settings: Settings) -> Container:
        pool = await asyncpg.create_pool(
            settings.database_url,
            min_size=settings.database_pool_min_size,
            max_size=settings.database_pool_max_size,
            command_timeout=settings.request_timeout_seconds,
        )
        records = PostgresRecordRepository(pool)
        audit_repository = PostgresAuditRepository(pool)
        revocations = PostgresRevocationStore(pool)
        model = cls._build_model(settings)
        audit = AuditTrail(audit_repository, settings.audit_hmac_key.get_secret_value())
        rate_limiter = PostgresFixedWindowRateLimiter(
            pool,
            signing_key=settings.audit_hmac_key.get_secret_value(),
            requests_per_minute=settings.rate_limit_requests_per_minute,
            burst=settings.rate_limit_burst,
        )
        policy = PolicyEngine()
        purpose_policy = PurposePolicy(settings.allowed_query_purposes)
        return cls(
            settings=settings,
            authenticator=TokenAuthenticator(settings),
            records=records,
            audit_repository=audit_repository,
            revocations=revocations,
            model=model,
            audit=audit,
            queries=QueryService(
                records=records,
                model=model,
                revocations=revocations,
                policy=policy,
                input_guard=InputGuard(),
                output_guard=OutputGuard(),
                audit=audit,
                rate_limiter=rate_limiter,
                max_records=settings.max_context_records,
                purpose_policy=purpose_policy,
                context_budget=ContextBudget(settings.max_context_bytes),
            ),
            rate_limiter=rate_limiter,
            policy_previews=PolicyPreviewService(
                records=records,
                policy=policy,
                audit=audit,
                max_records=settings.max_context_records,
            ),
            record_integrity=RecordIntegrity(settings.audit_hmac_key.get_secret_value()),
            pool=pool,
        )

    @staticmethod
    def _build_model(settings: Settings) -> ModelProvider:
        if settings.model_provider == "openai-compatible":
            return OpenAICompatibleModelProvider(
                base_url=settings.model_base_url,
                api_key=settings.model_api_key.get_secret_value(),
                model=settings.model_name,
                timeout_seconds=settings.request_timeout_seconds,
            )
        return DeterministicModelProvider()

    @staticmethod
    def _build_rate_limiter(settings: Settings) -> InMemoryTokenBucket:
        return InMemoryTokenBucket(
            requests_per_minute=settings.rate_limit_requests_per_minute,
            burst=settings.rate_limit_burst,
            max_identities=settings.rate_limit_max_identities,
        )

    async def close(self) -> None:
        close_model = getattr(self.model, "close", None)
        if close_model is not None:
            await close_model()
        if self.pool is not None:
            await self.pool.close()
