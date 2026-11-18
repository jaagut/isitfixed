"""Hourly, checksum-verified inventory of bundled LTS 20 VFS descriptors."""

import asyncio
import hashlib
import io
import json
import logging
import tempfile
import time
import zipfile

from .cache import RETENTION
from .errors import log_failure
from .fetch import MIB, download_to, read_limited
from .jobs import HourlyJob

FEED = "https://s3.amazonaws.com/help-deepsecurity-trendmicro/Resources/CustomScripts/download-center/data/ds-dlc-feed-src/en-us/products_lts.json"
FEED_LIMIT, FEED_DEADLINE = 32 * MIB, 120
AGENT_LIMIT, AGENT_DEADLINE = 300 * MIB, 600
# Agent archives up to this size stay in memory; larger ones spool to a temporary file (/tmp in the container).
SPOOL_IN_MEMORY = 8 * MIB
DOWNLOAD_PREFIX = "https://files.trendmicro.com/products/deepsecurity/en/20.0/"
STREAMS = {
    **{f"rhel{v}": f"RedHat_EL{v}" for v in (8, 9, 10)},
    **{f"debian{v}": f"Debian_{v}" for v in (12, 13)},
    **{f"sles{v}": f"SuSE_{v}" for v in (15, 16)},
    **{f"ubuntu{v}": f"Ubuntu_{v[:2]}.{v[2:]}" for v in ("2004", "2204", "2404", "2604")},
}
logger = logging.getLogger("cve-desk.tmds")


def inspect_archive(source, card):
    """Verify the published SHA-256 and list bundled ``Plugin-VFS_Filter_<kernel>`` descriptors.

    ``source`` is the archive as bytes or a seekable binary file; nothing is extracted or executed.
    """
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    source.seek(0)
    if hashlib.file_digest(source, "sha256").hexdigest() != card["sha256"].lower():
        raise ValueError("Agent checksum mismatch")
    source.seek(0)
    prefix = "Plugin-VFS_Filter_"
    suffix = f"-{card['platform']}-{card['release']}."
    entries = []
    with zipfile.ZipFile(source) as archive:
        for name in archive.namelist():
            if name.startswith(prefix) and suffix in name and name.endswith(".dsp"):
                entries.append(name[len(prefix) : name.index(suffix)])
    return sorted(set(entries))


def latest_cards(feed):
    """The newest enabled LTS 20 agent card per supported OS stream and architecture."""
    cards = [
        c
        for g in feed
        if g.get("name") == "Agent"
        for c in g["cards"]
        if c.get("majorMinor") == "20.0" and not c.get("disabled") and c.get("platform") in STREAMS.values()
    ]
    latest = {}
    for card in cards:
        key = (card["platform"], card["filename"].split(".")[-2])
        if key not in latest or card["releaseTimestamp"] > latest[key]["releaseTimestamp"]:
            latest[key] = card
    return list(latest.values())


class Inventory(HourlyJob):
    name = "tmds-agents"

    async def run(self):
        feed = json.loads(await read_limited(self.client, FEED, limit=FEED_LIMIT, deadline=FEED_DEADLINE))
        # Start with the latest release for each OS/architecture stream; retain previously observed releases for
        # ten days after supersession. One failing archive does not block the others.
        failure = None
        for card in latest_cards(feed):
            self.beat = time.monotonic()
            try:
                await self.record(card)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                log_failure(f"{self.name} ({card.get('platform')})", error)
                failure = failure or error
        if failure:
            raise failure

    async def record(self, card):
        filename = card["filename"]
        product = next(p for p, stream in STREAMS.items() if stream == card["platform"])
        db = self.cache.db
        if db.execute("SELECT 1 FROM agents WHERE filename=?", (filename,)).fetchone():
            with db:
                db.execute("UPDATE agents SET seen=? WHERE filename=?", (self.clock(), filename))
            return
        url = card["download"]
        if not url.startswith(DOWNLOAD_PREFIX) or not filename.endswith(".zip"):
            return
        with tempfile.SpooledTemporaryFile(max_size=SPOOL_IN_MEMORY) as archive:
            await download_to(
                self.client, url, archive, limit=AGENT_LIMIT, deadline=AGENT_DEADLINE, follow_redirects=False
            )
            kernels = await asyncio.to_thread(inspect_archive, archive, card)
        payload = {k: card.get(k) for k in ("filename", "release", "platform", "download", "sha256", "releaseDate")}
        payload.update(kernels=kernels, checked=int(self.clock() * 1000), architecture=filename.split(".")[-2])
        with db:
            db.execute(
                "INSERT OR REPLACE INTO agents VALUES (?,?,?,?)", (filename, product, json.dumps(payload), self.clock())
            )

    def cleanup(self):
        with self.cache.db:
            self.cache.db.execute("DELETE FROM agents WHERE seen <= ?", (self.clock() - RETENTION,))

    def products(self):
        rows = self.cache.db.execute(
            "SELECT product,payload FROM agents WHERE seen > ? ORDER BY seen DESC", (self.clock() - RETENTION,)
        )
        result = {}
        for row in rows:
            result.setdefault(row["product"], []).append(json.loads(row["payload"]))
        return result

    def snapshot(self):
        return {"products": self.products(), **self.status(), "source": FEED}

    def counts(self):
        return {"releases": sum(len(items) for items in self.products().values())}
