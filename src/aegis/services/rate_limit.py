from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass

from aegis.errors import RateLimitError


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class NoopRateLimiter:
    async def enforce(self, identity: str) -> None:
        del identity


class InMemoryTokenBucket:
    """Concurrency-safe token bucket keyed by trusted principal identity."""

    def __init__(
        self,
        *,
        requests_per_minute: int,
        burst: int,
        max_identities: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if requests_per_minute < 1 or burst < 1 or max_identities < 1:
            raise ValueError("rate limit parameters must be positive")
        self._rate_per_second = requests_per_minute / 60
        self._burst = float(burst)
        self._max_identities = max_identities
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    async def enforce(self, identity: str) -> None:
        now = self._clock()
        async with self._lock:
            bucket = self._buckets.get(identity)
            if bucket is None:
                self._evict_oldest_if_full()
                bucket = _Bucket(tokens=self._burst, updated_at=now)
                self._buckets[identity] = bucket

            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(
                self._burst,
                bucket.tokens + elapsed * self._rate_per_second,
            )
            bucket.updated_at = now
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return

            retry_after = max(1, math.ceil((1 - bucket.tokens) / self._rate_per_second))
            raise RateLimitError(
                "request rate exceeded for this identity",
                details={"retry_after_seconds": retry_after},
            )

    def _evict_oldest_if_full(self) -> None:
        if len(self._buckets) < self._max_identities:
            return
        oldest = min(self._buckets, key=lambda key: self._buckets[key].updated_at)
        del self._buckets[oldest]
