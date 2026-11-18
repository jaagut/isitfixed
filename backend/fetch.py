"""Bounded HTTP downloads: every transfer has a size cap and an overall deadline.

httpx timeouts apply per network operation, so a server that drips one byte at a time could keep a download alive
forever; the ``asyncio.timeout`` around the whole transfer prevents that.
"""

import asyncio
import hashlib

from .errors import TooLarge

MIB = 1024 * 1024


def _check_declared(response, limit):
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise TooLarge()


async def read_limited(client, url, *, limit, deadline, **kwargs):
    """Return the (decoded) response body, raising ``TooLarge`` or ``TimeoutError``."""
    async with asyncio.timeout(deadline):
        async with client.stream("GET", url, **kwargs) as response:
            response.raise_for_status()
            _check_declared(response, limit)
            data = bytearray()
            async for part in response.aiter_bytes():
                data.extend(part)
                if len(data) > limit:
                    raise TooLarge()
    return bytes(data)


async def download_to(client, url, target, *, limit, deadline, **kwargs):
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
