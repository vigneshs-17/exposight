"""Request rate limits and resource quotas (v3.6b A7).

Rate limits are kept in memory, per process. Production runs uvicorn with
--workers 1 (compose.prod.yml), so there is one counter per client. With more
worker processes each would count separately and the effective limit would
multiply; that needs a shared store (for example Redis), which is not used.
Counters reset when the api restarts.

Quotas (domains, organizations, manual scans, alert emails) are counted in
PostgreSQL, so they survive restarts.
"""

import math
import threading
import time
from collections import deque

from fastapi import HTTPException, status

# --- Request rate limits (sliding 60-second window) ---
API_REQUESTS_PER_MINUTE_PER_USER = 60
UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP = 20
RATE_WINDOW_SECONDS = 60.0

# --- Quotas (database counts) ---
MAX_DOMAINS_PER_ORG = 10
MAX_OWNED_ORGS_PER_USER = 5
MAX_MANUAL_SCANS_PER_DOMAIN_PER_HOUR = 3
MAX_ALERT_EMAILS_PER_DOMAIN_PER_DAY = 20

# Remove idle keys every this many hits so memory stays bounded by active clients.
_SWEEP_EVERY_HITS = 1000


class SlidingWindowLimiter:
    """Thread-safe sliding-window counter keyed by an arbitrary string."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._hits_since_sweep = 0

    def hit(self, key: str, limit: int, window: float = RATE_WINDOW_SECONDS) -> float | None:
        """Record one request for key.

        Returns None if it is allowed, or the number of seconds until the
        client may retry if the limit is already used up (the request is then
        not counted).
        """
        now = self._clock()
        with self._lock:
            self._maybe_sweep(now, window)
            timestamps = self._hits.setdefault(key, deque())
            while timestamps and timestamps[0] <= now - window:
                timestamps.popleft()
            if len(timestamps) >= limit:
                return max(timestamps[0] + window - now, 0.0)
            timestamps.append(now)
            return None

    def reset(self) -> None:
        """Forget all counters (used by tests)."""
        with self._lock:
            self._hits.clear()
            self._hits_since_sweep = 0

    def _maybe_sweep(self, now: float, window: float) -> None:
        # ponytail: one sweep over all keys every N hits; a timer thread if this ever shows up
        self._hits_since_sweep += 1
        if self._hits_since_sweep < _SWEEP_EVERY_HITS:
            return
        self._hits_since_sweep = 0
        stale = [k for k, ts in self._hits.items() if not ts or ts[-1] <= now - window]
        for key in stale:
            del self._hits[key]


limiter = SlidingWindowLimiter()


def too_many_requests(retry_after: float, detail: str = "Too many requests") -> HTTPException:
    """Build a 429 response with a whole-second Retry-After header (at least 1)."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=detail,
        headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
    )


def enforce_rate_limit(key: str, limit: int) -> None:
    """Raise 429 if key has used up its per-minute limit."""
    retry_after = limiter.hit(key, limit)
    if retry_after is not None:
        raise too_many_requests(retry_after)


def quota_exceeded(detail: str) -> HTTPException:
    """Build the 403 response used when a fixed-size quota is full."""
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
