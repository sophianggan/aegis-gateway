"""Core domain contracts shared across gateway layers."""

from aegis.domain.models import (
    AuditBundle,
    AuditEvent,
    Classification,
    DataField,
    Principal,
    QueryRequest,
    QueryResponse,
    Record,
)

__all__ = [
    "AuditBundle",
    "AuditEvent",
    "Classification",
    "DataField",
    "Principal",
    "QueryRequest",
    "QueryResponse",
    "Record",
]
