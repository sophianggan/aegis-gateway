import pytest

from aegis.errors import RateLimitError
from aegis.services.rate_limit import InMemoryTokenBucket, PostgresFixedWindowRateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def test_allows_configured_burst_then_returns_retry_time() -> None:
    clock = Clock()
    limiter = InMemoryTokenBucket(requests_per_minute=60, burst=2, clock=clock)

    await limiter.enforce("analyst")
    await limiter.enforce("analyst")
    with pytest.raises(RateLimitError) as captured:
        await limiter.enforce("analyst")

    assert captured.value.details == {"retry_after_seconds": 1}


async def test_refills_tokens_over_time() -> None:
    clock = Clock()
    limiter = InMemoryTokenBucket(requests_per_minute=60, burst=1, clock=clock)
    await limiter.enforce("analyst")
    clock.now = 1.0
    await limiter.enforce("analyst")


async def test_limits_identities_independently() -> None:
    clock = Clock()
    limiter = InMemoryTokenBucket(requests_per_minute=1, burst=1, clock=clock)
    await limiter.enforce("alpha")
    await limiter.enforce("bravo")
    with pytest.raises(RateLimitError):
        await limiter.enforce("alpha")


async def test_evicts_oldest_bucket_at_cardinality_limit() -> None:
    clock = Clock()
    limiter = InMemoryTokenBucket(
        requests_per_minute=1,
        burst=1,
        max_identities=2,
        clock=clock,
    )
    await limiter.enforce("oldest")
    clock.now = 1
    await limiter.enforce("newer")
    clock.now = 2
    await limiter.enforce("newest")
    await limiter.enforce("oldest")


def test_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        InMemoryTokenBucket(requests_per_minute=0, burst=1)


def test_distributed_limiter_pseudonymizes_identity_deterministically() -> None:
    limiter = PostgresFixedWindowRateLimiter(
        None,  # type: ignore[arg-type]
        signing_key="distributed-limit-key-long-enough",
        requests_per_minute=10,
        burst=2,
    )
    digest = limiter._identity_hash("user@example.test")
    assert len(digest) == 64
    assert "user@example.test" not in digest
    assert digest == limiter._identity_hash("user@example.test")
