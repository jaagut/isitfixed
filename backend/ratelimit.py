"""In-memory token-bucket rate limiting keyed by a keyed hash of the client address.

Client addresses are never stored: buckets are keyed by HMAC-SHA256(key, ip) truncated to 16 bytes, where the key is
random, held only in memory and replaced every 24 hours (which also resets all buckets). Nothing is persisted or
logged, and memory is bounded by dropping the least recently used buckets.
"""

import hashlib
import hmac
import math
import secrets
import time
from collections import OrderedDict

from starlette.responses import JSONResponse

ROTATE_AFTER = 24 * 3600
MAX_BUCKETS = 20_000


class RateLimiter:
    def __init__(self, clock=time.monotonic, max_buckets=MAX_BUCKETS, rotate_after=ROTATE_AFTER):
        self.clock, self.max_buckets, self.rotate_after = clock, max_buckets, rotate_after
        self.buckets: OrderedDict[tuple[str, bytes], tuple[float, float]] = OrderedDict()
        self._rotate()

    def _rotate(self):
        self._key = secrets.token_bytes(32)
        self._rotated = self.clock()
        self.buckets.clear()

    def client_key(self, address):
        if self.clock() - self._rotated >= self.rotate_after:
            self._rotate()
        return hmac.new(self._key, (address or "unknown").encode(), hashlib.sha256).digest()[:16]

    def hit(self, budget, client, per_minute):
        """Take one token from ``budget`` for ``client`` (a ``client_key`` or ``b""`` for a global budget).

        Returns 0 when allowed, otherwise the number of seconds until a token is available. A budget of 0 is off.
        """
        if per_minute <= 0:
            return 0
        now = self.clock()
        key = (budget, client)
        tokens, updated = self.buckets.pop(key, (float(per_minute), now))
        tokens = min(float(per_minute), tokens + (now - updated) * per_minute / 60)
        allowed = tokens >= 1
        if allowed:
            tokens -= 1
        self.buckets[key] = (tokens, now)
        while len(self.buckets) > self.max_buckets:
            self.buckets.popitem(last=False)
        return 0 if allowed else max(1, math.ceil((1 - tokens) * 60 / per_minute))

    def refund(self, budget, client, per_minute):
        """Return a token taken by ``hit`` (used when a later budget rejects the same request)."""
        if per_minute > 0 and (entry := self.buckets.get((budget, client))):
            self.buckets[(budget, client)] = (min(float(per_minute), entry[0] + 1), entry[1])


def client_address(scope):
    # Uvicorn replaces the client with X-Forwarded-For only for proxies listed in FORWARDED_ALLOW_IPS.
    client = scope.get("client")
    return client[0] if client else "unknown"


def too_many(retry_after, detail):
    return JSONResponse({"detail": detail}, status_code=429, headers={"Retry-After": str(retry_after)})


class RateLimitMiddleware:
    """Applies the per-client budget for all /api requests (except /api/health)."""

    def __init__(self, app, limiter, per_minute, on_reject=None):
        self.app, self.limiter, self.per_minute, self.on_reject = app, limiter, per_minute, on_reject

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] == "http" and path.startswith("/api/") and path != "/api/health":
            client = self.limiter.client_key(client_address(scope))
            if wait := self.limiter.hit("requests", client, self.per_minute):
                if self.on_reject:
                    self.on_reject("requests")
                response = too_many(wait, f"Too many requests. Try again in {wait} seconds.")
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
