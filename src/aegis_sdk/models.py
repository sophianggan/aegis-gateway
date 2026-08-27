from __future__ import annotations

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

