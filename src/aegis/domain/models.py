from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_field_names(fields: dict[str, DataField]) -> dict[str, DataField]:
    for name in fields:
        if not name or len(name) > 64:
            raise ValueError("field names must contain between 1 and 64 characters")
        if not name[0].isalpha() or any(
            not (character.isalnum() or character in "_.-") for character in name
        ):
            raise ValueError(
                "field names must start with a letter and use letters, digits, _, ., or -"
            )
    return fields


def _normalize_source(source: str) -> str:
    normalized = source.strip()
    if not normalized:
        raise ValueError("source must not be blank")
    return normalized


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
    TOKEN_REVOKE = "token.revoke"  # noqa: S105
    RECORD_DELETE = "record.delete"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str = Field(min_length=1, max_length=200)
    clearance: Classification
    compartments: frozenset[str] = Field(default_factory=frozenset, max_length=50)
    roles: frozenset[str] = Field(default_factory=frozenset, max_length=50)
    token_id: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("compartments", "roles", mode="before")
    @classmethod
    def normalize_sets(cls, value: Any) -> frozenset[str]:
        normalized = frozenset(
            str(item).strip().lower() for item in (value or []) if str(item).strip()
        )
        if any(len(item) > 64 for item in normalized):
            raise ValueError("role and compartment names must contain at most 64 characters")
        return normalized


class DataField(BaseModel):
    """A value plus the policy metadata needed to decide whether it may leave."""

    model_config = ConfigDict(frozen=True)

    value: Any
    classification: Classification = Classification.INTERNAL
    compartments: frozenset[str] = Field(default_factory=frozenset, max_length=50)
    exportable: bool = True

    @field_validator("classification", mode="before")
    @classmethod
    def parse_classification(cls, value: Any) -> Classification:
        return Classification.parse(value)

    @field_validator("compartments", mode="before")
    @classmethod
    def normalize_compartments(cls, value: Any) -> frozenset[str]:
        normalized = frozenset(
            str(item).strip().lower() for item in (value or []) if str(item).strip()
        )
        if any(len(item) > 64 for item in normalized):
            raise ValueError("compartment names must contain at most 64 characters")
        return normalized


class Record(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, DataField]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        return _normalize_source(value)

    @field_validator("fields")
    @classmethod
    def validate_field_names(cls, value: dict[str, DataField]) -> dict[str, DataField]:
        return _validate_field_names(value)


class RecordCreate(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, DataField] = Field(min_length=1, max_length=200)

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        return _normalize_source(value)

    @field_validator("fields")
    @classmethod
    def validate_field_names(cls, value: dict[str, DataField]) -> dict[str, DataField]:
        return _validate_field_names(value)


class RecordReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    field_count: int
    highest_classification: Classification
    integrity_algorithm: str = "HMAC-SHA256"
    integrity_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class RecordDeletionReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    deleted: bool


class TokenRevocationRequest(BaseModel):
    token_id: str = Field(min_length=1, max_length=200)
    reason_code: str = Field(default="administrative", pattern=r"^[a-z0-9][a-z0-9-]{1,49}$")


class TokenRevocationReceipt(BaseModel):
    request_id: UUID
    revoked: bool = True


class PolicyDecision(BaseModel):
    decision: Decision
    allowed_fields: dict[str, Any] = Field(default_factory=dict)
    filtered_fields: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class PolicyPreviewRequest(BaseModel):
    record_ids: list[UUID] = Field(min_length=1, max_length=100)

    @field_validator("record_ids")
    @classmethod
    def reject_duplicate_record_ids(cls, value: list[UUID]) -> list[UUID]:
        if len(value) != len(set(value)):
            raise ValueError("record_ids must not contain duplicates")
        return value


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
    metadata: dict[str, str] = Field(default_factory=dict, max_length=20)
    require_all_records: bool = False

    @field_validator("query")
    @classmethod
    def reject_blank_query(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("query must not be blank")
        return cleaned

    @field_validator("record_ids")
    @classmethod
    def reject_duplicate_record_ids(cls, value: list[UUID]) -> list[UUID]:
        if len(value) != len(set(value)):
            raise ValueError("record_ids must not contain duplicates")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key, item in value.items():
            clean_key = key.strip().lower()
            clean_value = item.strip()
            if not clean_key or len(clean_key) > 64:
                raise ValueError("metadata keys must contain between 1 and 64 characters")
            if len(clean_value) > 256:
                raise ValueError("metadata values must contain at most 256 characters")
            if clean_key in normalized:
                raise ValueError("metadata keys must be unique after normalization")
            normalized[clean_key] = clean_value
        return normalized


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


class AuditCheckpoint(BaseModel):
    version: str = "aegis.checkpoint.v1"
    request_id: UUID
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_count: int = Field(ge=1)
    chain_head: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature_algorithm: str = "HMAC-SHA256"
    signature: str = Field(default="", pattern=r"^$|^[a-f0-9]{64}$")
