from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    RESTRICTED = 30


class ClassifiedValue(BaseModel):
    value: Any
    classification: Classification = Classification.INTERNAL
    compartments: set[str] = Field(default_factory=set)
    exportable: bool = True


class RecordInput(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str = Field(min_length=1, max_length=100)
    fields: dict[str, ClassifiedValue] = Field(min_length=1, max_length=200)


class RecordReceipt(BaseModel):
    request_id: UUID
    record_id: UUID
    field_count: int
    highest_classification: Classification


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
    version: str
    request_id: UUID
    generated_at: datetime
    event_count: int
    chain_head: str
    events: list[AuditEvent]
    signature_algorithm: str
    bundle_signature: str


class AuditPage(BaseModel):
    events: list[AuditEvent]
    next_sequence: int | None
    has_more: bool
