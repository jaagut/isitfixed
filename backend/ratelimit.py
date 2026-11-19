"""In-memory token-bucket rate limiting keyed by the shortened client address.

The full client address is only read while handling the request: buckets are keyed by its network prefix (IPv4 /24,
IPv6 /48), which is shared by many people and greatly reduces identifiability. Nothing is persisted or logged; a
bucket is dropped once it has refilled (one minute after its last use), and memory is bounded by dropping the least
recently used buckets first.
"""

import ipaddress
import math
import time
from collections import OrderedDict

from starlette.responses import JSONResponse

MAX_BUCKETS = 20_000
WINDOW = 60  # seconds in which an emptied bucket refills completely
IPV4_PREFIX, IPV6_PREFIX = 24, 48


def shorten(address):
    """The /24 (IPv4) or /48 (IPv6) network of ``address``; ``"unknown"`` for anything that is not an IP address."""
    try:
        ip = ipaddress.ip_address((address or "").split("%", 1)[0])
    except ValueError:
        return "unknown"
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    prefix = IPV4_PREFIX if ip.version == 4 else IPV6_PREFIX
    return str(ipaddress.ip_network((ip, prefix), strict=False))


class RateLimiter:
    def __init__(self, clock=time.monotonic, max_buckets=MAX_BUCKETS):
        self.clock, self.max_buckets = clock, max_buckets
        # (budget, shortened address) -> (tokens, last update); least recently used first.
        self.buckets: OrderedDict[tuple[str, str], tuple[float, float]] = OrderedDict()

    def client_key(self, address):
        return shorten(address)

    def _expire(self, now):
        # Buckets untouched for a full window are full again, i.e. identical to a missing bucket.
        while self.buckets:
            key, (_, updated) = next(iter(self.buckets.items()))
            if now - updated < WINDOW:
                break
            del self.buckets[key]

    def hit(self, budget, client, per_minute):
        """Take one token from ``budget`` for ``client`` (a ``client_key`` or ``""`` for a global budget).

        Returns 0 when allowed, otherwise the number of seconds until a token is available. A budget of 0 is off.
        """
        if per_minute <= 0:
            return 0
        now = self.clock()
        self._expire(now)
        key = (budget, client)
        tokens, updated = self.buckets.pop(key, (float(per_minute), now))
        tokens = min(float(per_minute), tokens + (now - updated) * per_minute / WINDOW)
        allowed = tokens >= 1
        if allowed:
            tokens -= 1
        self.buckets[key] = (tokens, now)
        while len(self.buckets) > self.max_buckets:
            self.buckets.popitem(last=False)
        return 0 if allowed else max(1, math.ceil((1 - tokens) * WINDOW / per_minute))

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
