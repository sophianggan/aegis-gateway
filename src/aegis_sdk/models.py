from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


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
