from __future__ import annotations

import hashlib
import hmac
import json

from aegis.domain.models import Record


class RecordIntegrity:
    """Create stable keyed digests without exposing classified record contents."""

    def __init__(self, signing_key: str) -> None:
        if len(signing_key) < 16:
            raise ValueError("record integrity key must contain at least 16 characters")
        self._key = signing_key.encode()

    def digest(self, record: Record) -> str:
        payload = {
            "version": "aegis.record.v1",
            "id": str(record.id),
            "source": record.source,
            "fields": {
                name: field.model_dump(mode="json") for name, field in sorted(record.fields.items())
            },
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()

    def verify(self, record: Record, expected_digest: str) -> bool:
        return hmac.compare_digest(self.digest(record), expected_digest)
