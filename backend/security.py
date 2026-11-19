"""HTTP hardening middleware: security headers, selective compression and request body limits."""

from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import JSONResponse

PERMISSIONS_POLICY = (
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()"
)


def content_security_policy(connect_src=(), https=False):
    connect = " ".join(("'self'", *connect_src))
    policy = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        f"connect-src {connect}",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
    # Only when the request arrived over HTTPS (directly or via a trusted proxy): on plain-HTTP hosts such as a
    # LAN address, upgrading same-origin subresources to https:// would break the page.
    if https:
        policy.append("upgrade-insecure-requests")
    return "; ".join(policy)


class SecurityHeaders:
    """Adds security headers to every response (pure ASGI, so streaming responses are not buffered)."""

    def __init__(self, app, connect_src=(), hsts=False):
        self.app, self.connect_src, self.hsts = app, tuple(connect_src), hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = content_security_policy(self.connect_src, https=scope.get("scheme") == "https")

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("Content-Security-Policy", csp)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = PERMISSIONS_POLICY
                headers["Cross-Origin-Opener-Policy"] = "same-origin"
                headers["Cross-Origin-Resource-Policy"] = "same-origin"
                headers["X-Frame-Options"] = "DENY"
                if self.hsts:  # browsers ignore it on plain HTTP
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, wrapped)


class SelectiveGZip:
    """GZip for regular responses; streamed NDJSON progress must reach the browser line by line uncompressed."""

    def __init__(self, app, minimum_size=1024, skip_suffixes=("/stream",)):
        self.app = app
        self.gzip = GZipMiddleware(app, minimum_size=minimum_size, compresslevel=6)
        self.skip_suffixes = skip_suffixes

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not scope.get("path", "").endswith(self.skip_suffixes):
            await self.gzip(scope, receive, send)
        else:
            await self.app(scope, receive, send)


class BodyLimit:
    """Rejects request bodies larger than ``limit`` bytes with 413, whether declared or streamed (chunked).

    A streamed body is counted while the app reads it. Once it exceeds the limit, the 413 response is sent at once,
    the app sees a client disconnect, and anything the app tries to send afterwards (such as a 400 for the body it
    could not read) is discarded.
    """

    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > self.limit:
            await too_large(scope, receive, send)
            return
        received = 0
        rejected = started = False

        async def guarded_send(message):
            nonlocal started
            if rejected:
                return
            started = started or message["type"] == "http.response.start"
            await send(message)

        async def limited():
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.limit:
                    rejected = True
                    if not started:
                        await too_large(scope, receive, send)
                    return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, limited, guarded_send)
        except Exception:
            if not rejected:
                raise


async def too_large(scope, receive, send):
    await JSONResponse({"detail": "Request body too large."}, status_code=413)(scope, receive, send)
