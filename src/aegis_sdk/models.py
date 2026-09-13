from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    RESTRICTED = 30


class ClassifiedValue(BaseModel):
    value: Any
    classification: Classification = Classification.INTERNAL
    compartments: set[str] = Field(default_factory=set, max_length=50)
    exportable: bool = True

    @field_validator("compartments", mode="before")
    @classmethod
    def normalize_compartments(cls, value: Any) -> Any:
        if value is None:
            return set()
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        normalized = {str(item).strip().lower() for item in value if str(item).strip()}
        if any(len(item) > 64 for item in normalized):
            raise ValueError("compartment names must contain at most 64 characters")
        return normalized


class RecordInput(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, ClassifiedValue] = Field(min_length=1, max_length=200)

    @field_validator("source", mode="before")
    @classmethod
    def normalize_source(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        if not normalized:
            raise ValueError("source must not be blank")
        return normalized

    @field_validator("fields")
    @classmethod
    def validate_field_names(cls, value: dict[str, ClassifiedValue]) -> dict[str, ClassifiedValue]:
        for name in value:
            if not name or len(name) > 64:
                raise ValueError("field names must contain between 1 and 64 characters")
            if not name[0].isalpha() or any(
                not (character.isalnum() or character in "_.-") for character in name
            ):
                raise ValueError(
                    "field names must start with a letter and use letters, digits, _, ., or -"
                )
        return value


class RecordReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    field_count: int
    highest_classification: Classification
    integrity_algorithm: Literal["HMAC-SHA256"]
    integrity_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class RecordDeletionReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    deleted: bool


class TokenRevocationReceipt(BaseModel):
    request_id: UUID
    revoked: bool


class Citation(BaseModel):
    record_id: UUID
    source: str
    disclosed_fields: list[str]


class QueryResult(BaseModel):
    request_id: UUID
    answer: str
    citations: list[Citation]
    filtered_field_count: int
    policy_summary: str
    missing_record_ids: list[UUID] = Field(default_factory=list)


class RecordPolicyPreview(BaseModel):
    record_id: UUID
    source: str
    decision: str
    allowed_fields: list[str]
    filtered_fields: list[str]
    reasons: list[str]


class PolicyPreview(BaseModel):
    request_id: UUID
    records: list[RecordPolicyPreview]
    missing_record_ids: list[UUID]


class AuditEvent(BaseModel):
    id: UUID
    request_id: UUID
    sequence: int
    occurred_at: datetime
    actor: str
    action: str
    decision: str
    resource_ids: list[str]
    details: dict[str, Any]
    previous_hash: str
    event_hash: str


class AuditBundle(BaseModel):
    version: Literal["aegis.audit.v1"]
    request_id: UUID
    generated_at: datetime
    event_count: int
    chain_head: str
    events: list[AuditEvent]
    signature_algorithm: Literal["HMAC-SHA256"]
    bundle_signature: str


class AuditVerification(BaseModel):
    valid: bool = Field(strict=True)


class AuditPage(BaseModel):
    events: list[AuditEvent]
    next_sequence: int | None
    has_more: bool


class AuditCheckpoint(BaseModel):
    version: Literal["aegis.checkpoint.v1"]
    request_id: UUID
    generated_at: datetime
    event_count: int
    chain_head: str
    signature_algorithm: Literal["HMAC-SHA256"]
    signature: str
