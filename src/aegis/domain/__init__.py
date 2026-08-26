"""Core domain contracts shared across gateway layers."""

from aegis.domain.models import (
    AuditEvent,
    Classification,
    DataField,
    Principal,
    QueryRequest,
    QueryResponse,
    Record,
)

__all__ = [
    "AuditEvent",
    "Classification",
    "DataField",
    "Principal",
    "QueryRequest",
    "QueryResponse",
    "Record",
]

