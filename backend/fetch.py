"""Bounded HTTP downloads: every transfer has a size cap and an overall deadline.

httpx timeouts apply per network operation, so a server that drips one byte at a time could keep a download alive
forever; the ``asyncio.timeout`` around the whole transfer prevents that. Bodies held in memory additionally count
against a shared ``Budget``, so many concurrent downloads cannot add up to more than a fixed number of bytes.
"""

import asyncio
import hashlib
from contextlib import contextmanager

from .errors import Busy, TooLarge

MIB = 1024 * 1024


class Budget:
    """Bytes that all in-flight in-memory downloads may buffer together.

    Downloads take bytes as they arrive and never wait for them (so they cannot deadlock each other); a download that
    would exceed the budget fails with ``Busy`` and frees what it held.
    """

    def __init__(self, limit):
        self.limit, self.used = limit, 0

    @contextmanager
    def hold(self):
        held = 0

        def take(count):
            nonlocal held
            if self.used + count > self.limit:
                raise Busy()
            self.used += count
            held += count

        try:
            yield take
        finally:
            self.used -= held


def _check_declared(response, limit):
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise TooLarge()


async def read_limited(client, url, *, limit, deadline=None, take=None, **kwargs):
    """Return the (decoded) response body, raising ``TooLarge``, ``Busy`` or ``TimeoutError``.

    ``take(count)`` (from ``Budget.hold``) accounts for buffered bytes; the caller keeps holding them while it uses
    the result. ``deadline=None`` leaves the overall deadline to the caller.
    """
    async with asyncio.timeout(deadline):
        async with client.stream("GET", url, **kwargs) as response:
            response.raise_for_status()
            _check_declared(response, limit)
            data = bytearray()
            async for part in response.aiter_bytes():
                if len(data) + len(part) > limit:
                    raise TooLarge()
                if take:
                    take(2 * len(part))  # the buffer plus the final copy
                data.extend(part)
    return bytes(data)


async def download_to(client, url, target, *, limit, deadline=None, **kwargs):
    """Stream the response into a writable binary file; return its SHA-256 hex digest."""
    digest = hashlib.sha256()
    size = 0
    async with asyncio.timeout(deadline):
        async with client.stream("GET", url, **kwargs) as response:
            response.raise_for_status()
            _check_declared(response, limit)
            async for part in response.aiter_bytes():
                size += len(part)
                if size > limit:
                    raise TooLarge()
                digest.update(part)
                target.write(part)
    target.flush()
    return digest.hexdigest()
