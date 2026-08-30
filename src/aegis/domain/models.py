from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Classification(IntEnum):
    """Ordered sensitivity labels; a principal may access its level and below."""

    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    RESTRICTED = 30

    @classmethod
    def parse(cls, value: str | int | Classification) -> Classification:
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


class Decision(StrEnum):
    ALLOW = "allow"
    FILTER = "filter"
    DENY = "deny"


class AuditAction(StrEnum):
    AUTHENTICATE = "authenticate"
    RETRIEVE = "retrieve"
    POLICY_EVALUATE = "policy.evaluate"
    MODEL_INVOKE = "model.invoke"
    OUTPUT_SCAN = "output.scan"
    REQUEST_COMPLETE = "request.complete"
    REQUEST_DENY = "request.deny"
    RECORD_UPSERT = "record.upsert"
    POLICY_PREVIEW = "policy.preview"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str = Field(min_length=1, max_length=200)
    clearance: Classification
    compartments: frozenset[str] = Field(default_factory=frozenset)
    roles: frozenset[str] = Field(default_factory=frozenset)
    token_id: str | None = None

    @field_validator("compartments", "roles", mode="before")
    @classmethod
    def normalize_sets(cls, value: Any) -> frozenset[str]:
        return frozenset(str(item).strip().lower() for item in (value or []) if str(item).strip())


class DataField(BaseModel):
    """A value plus the policy metadata needed to decide whether it may leave."""

    model_config = ConfigDict(frozen=True)

    value: Any
    classification: Classification = Classification.INTERNAL
    compartments: frozenset[str] = Field(default_factory=frozenset)
    exportable: bool = True

    @field_validator("classification", mode="before")
    @classmethod
    def parse_classification(cls, value: Any) -> Classification:
        return Classification.parse(value)

    @field_validator("compartments", mode="before")
    @classmethod
    def normalize_compartments(cls, value: Any) -> frozenset[str]:
        return frozenset(str(item).strip().lower() for item in (value or []) if str(item).strip())


class Record(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, DataField]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RecordCreate(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, DataField] = Field(min_length=1, max_length=200)


class RecordReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    field_count: int
    highest_classification: Classification
    integrity_algorithm: str = "HMAC-SHA256"
    integrity_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class PolicyDecision(BaseModel):
    decision: Decision
    allowed_fields: dict[str, Any] = Field(default_factory=dict)
    filtered_fields: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class PolicyPreviewRequest(BaseModel):
    record_ids: list[UUID] = Field(min_length=1, max_length=100)


class RecordPolicyPreview(BaseModel):
    record_id: UUID
    source: str
    decision: Decision
    allowed_fields: list[str]
    filtered_fields: list[str]
    reasons: list[str]


class PolicyPreviewResponse(BaseModel):
    request_id: UUID
    records: list[RecordPolicyPreview]
    missing_record_ids: list[UUID]


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=8_000)
    record_ids: list[UUID] = Field(default_factory=list, max_length=100)
    purpose: str = Field(default="analysis", min_length=1, max_length=200)
    metadata: dict[str, str] = Field(default_factory=dict)
    require_all_records: bool = False

    @field_validator("query")
    @classmethod
    def reject_blank_query(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("query must not be blank")
        return cleaned


class Citation(BaseModel):
    record_id: UUID
    source: str
    disclosed_fields: list[str]


class QueryResponse(BaseModel):
    request_id: UUID
    answer: str
    citations: list[Citation]
    filtered_field_count: int
    policy_summary: str
    missing_record_ids: list[UUID] = Field(default_factory=list)


class AuditEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    sequence: int = Field(ge=0)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str
    action: AuditAction
    decision: Decision
    resource_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    event_hash: str = ""


class AuditBundle(BaseModel):
    version: str = "aegis.audit.v1"
    request_id: UUID
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_count: int = Field(ge=1)
    chain_head: str
    events: list[AuditEvent]
    signature_algorithm: str = "HMAC-SHA256"
    bundle_signature: str = ""


class AuditPage(BaseModel):
    events: list[AuditEvent]
    next_sequence: int | None = None
    has_more: bool = False
