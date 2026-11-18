"""Map upstream failures to short, user-facing descriptions without leaking raw exception text."""

import json
import logging
import re
import socket
import ssl
import zipfile
from time import gmtime, strftime

import httpx

logger = logging.getLogger("cve-desk.sources")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){3,7}(?![\w:])")
_DNS_HINTS = ("name resolution", "name or service not known", "nodename nor servname", "no address associated")


class NotPublished(Exception):  # noqa: N818 - a "not published" signal, not an error; the name is part of the API
    """The source has no document for this CVE (HTTP 404)."""


class TooLarge(Exception):  # noqa: N818 - reads naturally as "response too large"
    """A download exceeded its size cap."""


class Paused(Exception):  # noqa: N818 - a circuit-breaker state, not an upstream error
    """The source is in backoff after repeated failures; upstream was not contacted."""

    def __init__(self, until):
        super().__init__("paused")
        self.until = until


def scrub(text):
    """Remove IP addresses from text that may reach logs."""
    return _IPV6.sub("[addr]", _IPV4.sub("[addr]", text))


def _chain(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _host(exc):
    try:
        return exc.request.url.host or "source"
    except (AttributeError, RuntimeError):
        return "source"


def describe(exc):
    """Short, user-facing description of a source failure (never raw exception text)."""
    if isinstance(exc, NotPublished):
        return str(exc)
    if isinstance(exc, Paused):
        return (
            f"temporarily paused after repeated failures; next attempt after {strftime('%H:%M', gmtime(exc.until))} UTC"
        )
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} from {_host(exc)}"
    if isinstance(exc, TooLarge):
        return "response too large"
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return "request timed out"
    if isinstance(exc, httpx.RequestError):
        chain = list(_chain(exc))
        if any(isinstance(e, socket.gaierror) for e in chain) or any(
            hint in str(e).lower() for e in chain for hint in _DNS_HINTS
        ):
            return "DNS lookup failed"
        if any(isinstance(e, ssl.SSLError) for e in chain) or any(
            "ssl" in str(e).lower() or "certificate" in str(e).lower() for e in chain
        ):
            return "TLS error"
        return f"connection failed ({_host(exc)})"
    if isinstance(exc, (ValueError, KeyError, TypeError, IndexError, json.JSONDecodeError, zipfile.BadZipFile)):
        return "invalid data from source"
    return "unexpected error"


def log_failure(source, exc):
    """Log the technical detail of a failure server-side, without addresses or workspace ids."""
    if isinstance(exc, (NotPublished, Paused)):
        return
    detail = scrub(str(exc))[:300]
    logger.warning(
        "Source %s failed: %s (%s%s)", source, describe(exc), type(exc).__name__, f": {detail}" if detail else ""
    )
