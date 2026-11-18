"""Fetch official sources and normalize them to the browser's evidence schema."""

import asyncio
import json
import re
import sys
import tempfile
import time
from pathlib import Path

import httpx

from .errors import NotPublished, TooLarge, describe
from .feedindex import alpine_index, debian_index
from .fetch import MIB, Budget, download_to, read_limited

__all__ = ["DEADLINES", "FAMILIES", "HOUR", "PRODUCTS", "NotPublished", "Providers", "describe"]

HOUR = 3600
# Per-CVE documents should answer quickly; bulk feeds are large shared downloads.
DEADLINES = {"record": 30, "rhel": 30, "sles": 30, "ubuntu": 30, "debian": 150, "alpine": 150}
# Overall limits for one shared download, independent of how long any requester waits for it.
DOCUMENT_DEADLINE, BULK_DEADLINE = 30, 150
DOCUMENT_LIMIT = 128 * MIB
# Memory: per-CVE documents and Alpine feeds are buffered in memory and share one byte budget; at most a few documents
# download at once. Bulk feeds are fetched one at a time; the Debian dump (~90 MB) is spooled to disk and indexed by a
# child process (feedindex.py), and only compact per-CVE indexes are kept for up to an hour.
IN_FLIGHT_LIMIT = 192 * MIB
DOCUMENT_CONCURRENCY = 6
DEBIAN_LIMIT = 512 * MIB  # on disk
ALPINE_LIMIT = 32 * MIB
INDEX_LIMIT = 64 * MIB  # compact Debian index returned by the child process
INDEXER = Path(__file__).with_name("feedindex.py")
DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
ALPINE_URL = "https://secdb.alpinelinux.org/"
# SUSE lists public-cloud container-host images alongside the OS. They are
# separate products, so they are excluded from the SLES rows and counted instead.
SUSE_IMAGE = re.compile(r"\bimages? for\b|\bCHOST\b", re.I)


FAMILIES = {"rhel", "sles", "debian", "ubuntu", "alpine"}
PRODUCTS = {
    **{
        f"rhel{v}": ("rhel", re.compile(rf"\bred hat enterprise linux(?: {v}\b|[^()]*\(v\. {v}\))", re.I))
        for v in (8, 9, 10)
    },
    **{f"sles{v}": ("sles", re.compile(rf"\b(?:suse linux enterprise server|sles) {v}\b", re.I)) for v in (15, 16)},
    **{f"debian{v}": ("debian", code) for v, code in ((12, "bookworm"), (13, "trixie"))},
    **{
        f"ubuntu{v}": ("ubuntu", code)
        for v, code in (("2004", "focal"), ("2204", "jammy"), ("2404", "noble"), ("2604", "resolute"))
    },
    **{f"alpine{v.replace('.', '')}": ("alpine", v) for v in ("3.20", "3.21", "3.22", "3.23", "3.24")},
}


def evidence(name, status, source, **kwargs):
    return dict(
        name=name, status=status, source=source, affected=[], unaffected=[], fix=[], mitigation=[], links=[], **kwargs
    )


def csaf(doc, cve, family):
    if doc.get("document", {}).get("csaf_version") != "2.0":
        raise ValueError("Expected CSAF 2.0")
    vulnerability = next((v for v in doc.get("vulnerabilities", []) if v.get("cve", "").upper() == cve), None)
    if vulnerability is None:
        raise ValueError("CSAF document does not contain the requested CVE")
    tree = doc.get("product_tree", {})
    names, short = {}, {}

    def walk(branches, path=()):
        for branch in branches:
            context = (*path, branch.get("name", ""))
            if product := branch.get("product"):
                pid = product["product_id"]
                short[pid] = product.get("name", branch.get("name", ""))
                names[pid] = " ".join((*context, short[pid]))
            walk(branch.get("branches", []), context)

    walk(tree.get("branches", []))
    for product in tree.get("full_product_names", []):
        names[product["product_id"]] = short[product["product_id"]] = product["name"]
    relationships = {r["full_product_name"]["product_id"]: r for r in tree.get("relationships", [])}

    # Resolve references recursively, including relationships listed out of order.
    def resolve(pid, seen=None):
        seen = seen or set()
        if pid in seen:
            return ""
        if relation := relationships.get(pid):
            seen = seen | {pid}
            return " ".join(
                (
                    resolve(relation["product_reference"], seen),
                    resolve(relation["relates_to_product_reference"], seen),
                    relation["full_product_name"]["name"],
                )
            )
        return names.get(pid, pid.replace("_", " "))

    groups = {g["group_id"]: g.get("product_ids", []) for g in tree.get("product_groups", [])}
    source = "Red Hat VEX" if family == "rhel" else "SUSE CSAF"
    result, images = {}, set()
    for product, (group, pattern) in PRODUCTS.items():
        if group != family:
            continue
        items = []
        for key, base in (
            ("known_affected", "affected"),
            ("known_not_affected", "unaffected"),
            ("fixed", "fixed"),
            ("recommended", "recommended"),
            ("under_investigation", "unknown"),
        ):
            for pid in vulnerability.get("product_status", {}).get(key, []):
                full = resolve(pid)
                if not pattern.search(full):
                    continue
                if family == "sles" and SUSE_IMAGE.search(full):
                    images.add(pid)
                    continue
                rem = [
                    r
                    for r in vulnerability.get("remediations", [])
                    if (not r.get("product_ids") and not r.get("group_ids"))
                    or pid in r.get("product_ids", [])
                    or any(pid in groups.get(g, []) for g in r.get("group_ids", []))
                ]
                fixes = [r for r in rem if r.get("category") == "vendor_fix"]
                status = ("fixed" if fixes else "unknown") if base == "recommended" else base
                name = (
                    short.get(pid)
                    or relationships.get(pid, {}).get("full_product_name", {}).get("name")
                    or resolve(pid)
                )
                item = evidence(name, status, source)
                item.update(
                    affected=[name] if status == "affected" else [],
                    fix=[name] if status == "fixed" else [r["details"] for r in fixes if r.get("details")],
                    mitigation=[
                        r["details"]
                        for r in rem
                        if r.get("category") in ("mitigation", "workaround") and r.get("details")
                    ],
                    links=[r["url"] for r in fixes if r.get("url")],
                )
                if base == "recommended":
                    item["note"] = (
                        "Recommended patched build; vendor-fix remediation published."
                        if fixes
                        else "Recommended build; no explicit vendor-fix remediation published."
                    )
                items.append(item)
        result[product] = items
    metadata = {"sourceUpdated": doc.get("document", {}).get("tracking", {}).get("current_release_date")}
    if images:
        metadata["excludedImages"] = len(images)
    if family == "sles":
        metadata["advisories"] = [
            {"url": r["url"], "label": r["summary"].removeprefix("Advisory link for ")}
            for r in doc["document"].get("references", [])
            if r.get("summary", "").startswith("Advisory link for ") and r.get("url")
        ]
    return result, metadata


def ubuntu(doc, cve):
    if doc.get("id") != cve:
        raise ValueError("Ubuntu document does not match the CVE")
    result = {}
    for product, (family, code) in PRODUCTS.items():
        if family != "ubuntu":
            continue
        items = []
        for package in doc.get("packages", []):
            for status in package.get("statuses", []):
                if status.get("release_codename") != code:
                    continue
                state = status.get("status")
                mapped = (
                    "fixed"
                    if state == "released"
                    else "unaffected"
                    if state in ("not-affected", "DNE")
                    else "affected"
                    if state in ("needed", "pending", "ignored", "deferred")
                    else "unknown"
                )
                item = evidence(package["name"], mapped, "Ubuntu security tracker")
                item["note"] = (
                    f"{state}{': ' + status['description'] if status.get('description') else ''}{' · ' + status['pocket'] if status.get('pocket') else ''}"
                )
                if state == "released":
                    item["fix"] = [f"{package['name']} {status.get('description', '')}".strip()]
                items.append(item)
        if items and doc.get("mitigation"):
            items[0]["mitigation"] = [doc["mitigation"]]
        result[product] = items
    return result


def debian_codes():
    return [code for family, code in PRODUCTS.values() if family == "debian"]


def debian_evidence(entries):
    """Evidence per Debian product from the index entries ``[package, codename, status, fixed_version, nodsa]``."""
    result = {}
    for product, (family, code) in PRODUCTS.items():
        if family != "debian":
            continue
        items = []
        for package, codename, state, version, nodsa in entries:
            if codename != code:
                continue
            status = (
                ("unaffected" if version == "0" else "fixed" if version else "unknown")
                if state == "resolved"
                else "affected"
                if state == "open"
                else "unknown"
            )
            item = evidence(package, status, "Debian security tracker")
            item.update(fix=[f"{package} {version}"] if version and version != "0" else [], note=nodsa or "")
            items.append(item)
        result[product] = items
    return result


def debian(doc, cve):
    """Evidence from a full Debian tracker document (the app itself uses the compact index)."""
    return debian_evidence(debian_index(doc, debian_codes()).get(cve, []))


def alpine_evidence(entries):
    items = []
    for name, version in entries:
        item = evidence(name, "fixed", "Alpine secdb")
        item["fix"] = [f"{name} {version}"]
        items.append(item)
    return items


def alpine(doc, cve):
    return alpine_evidence(alpine_index(doc).get(cve, []))


async def _read_capped(stream, limit):
    data = bytearray()
    while chunk := await stream.read(1 << 20):
        data.extend(chunk)
        if len(data) > limit:
            raise TooLarge()
    return bytes(data)


class Providers:
    def __init__(self, client: httpx.AsyncClient, clock=time.time, spool_dir=None):
        self.client, self.clock, self.spool_dir = client, clock, spool_dir
        self.feeds, self.pending = {}, {}  # url -> (compact index, fetched at); url -> shared download task
        self.memory = Budget(IN_FLIGHT_LIMIT)
        self.documents = asyncio.Semaphore(DOCUMENT_CONCURRENCY)
        self.bulk = asyncio.Semaphore(1)

    def prune(self, clear=False):
        self.feeds = {url: item for url, item in self.feeds.items() if not clear and self.clock() - item[1] < HOUR}

    async def shared(self, url, work):
        """Run ``work()`` once per URL for all concurrent requesters; a cancelled requester does not cancel it."""
        if url in self.pending:
            return await asyncio.shield(self.pending[url])
        task = self.pending[url] = asyncio.create_task(work())
        # Mark the outcome as retrieved even when every requester has already given up.
        task.add_done_callback(lambda done: done.cancelled() or done.exception())
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self.pending.pop(url, None)
            else:
                task.add_done_callback(lambda _: self.pending.pop(url, None))

    async def get_json(self, url):
        """A per-CVE document; the deadline bounds the shared task itself, including waiting for admission."""

        async def download():
            async with asyncio.timeout(DOCUMENT_DEADLINE), self.documents:
                with self.memory.hold() as take:
                    data = await read_limited(self.client, url, limit=DOCUMENT_LIMIT, take=take)
                    return await asyncio.to_thread(json.loads, data)

        return await self.shared(url, download)

    async def get_feed(self, url, kind):
        """The compact index of a bulk feed (``kind`` "debian" or "alpine"), kept in memory for up to an hour."""
        self.prune()
        if url in self.feeds:
            return self.feeds[url][0]

        async def download():
            async with asyncio.timeout(BULK_DEADLINE), self.bulk:
                index = await (self._debian_index(url) if kind == "debian" else self._alpine_index(url))
            self.feeds[url] = (index, self.clock())
            return index

        return await self.shared(url, download)

    async def _alpine_index(self, url):
        with self.memory.hold() as take:
            data = await read_limited(self.client, url, limit=ALPINE_LIMIT, take=take)
            return await asyncio.to_thread(lambda: alpine_index(json.loads(data)))

    async def _debian_index(self, url):
        with tempfile.NamedTemporaryFile(prefix="isitfixed-feed-", suffix=".json", dir=self.spool_dir) as spool:
            await download_to(self.client, url, spool, limit=DEBIAN_LIMIT)
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-S",
                str(INDEXER),
                "debian",
                spool.name,
                *debian_codes(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                output = await _read_capped(process.stdout, INDEX_LIMIT)
                if await process.wait() != 0:
                    raise ValueError("Debian tracker data could not be indexed")
            finally:
                if process.returncode is None:
                    process.kill()
                # Drain the PIPE after killing: wait() alone can deadlock on buffered stdout.
                await process.communicate()
        index = {}
        for line in output.splitlines():
            cve, _, entries = line.partition(b"\t")
            index[cve.decode()] = entries
        return index

    async def get_document(self, url, missing):
        try:
            return await self.get_json(url)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise NotPublished(missing) from None
            raise

    async def record(self, cve):
        doc = await self.get_document(
            f"https://cveawg.mitre.org/api/cve/{cve}",
            "CVE ID not found in the CVE Program (not published, reserved or mistyped).",
        )
        if doc.get("cveMetadata", {}).get("cveId") != cve or not doc.get("containers"):
            raise ValueError("Invalid CVE record")
        return doc

    async def vendor(self, family, cve):
        year = cve.split("-")[1]
        metadata = {}
        if family in ("rhel", "sles"):
            url = (
                f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve.lower()}.json"
                if family == "rhel"
                else f"https://ftp.suse.com/pub/projects/security/csaf-vex/{max(2023, int(year))}/{cve.lower()}.json"
            )
            result, metadata = csaf(
                await self.get_document(
                    url, f"{'Red Hat' if family == 'rhel' else 'SUSE'} has not published a document for this CVE yet."
                ),
                cve,
                family,
            )
        elif family == "ubuntu":
            url = f"https://ubuntu.com/security/cves/{cve}.json"
            result = ubuntu(
                await self.get_document(url, "Ubuntu has not published a tracker entry for this CVE yet."), cve
            )
        elif family == "debian":
            url = DEBIAN_URL
            entries = (await self.get_feed(url, "debian")).get(cve)
            result = debian_evidence(json.loads(entries) if entries else [])
        elif family == "alpine":
            url, result = ALPINE_URL, {}
            for product, (group, version) in PRODUCTS.items():
                if group != "alpine":
                    continue
                indexes = await asyncio.gather(
                    *(self.get_feed(f"{url}v{version}/{repo}.json", "alpine") for repo in ("main", "community"))
                )
                result[product] = [item for index in indexes for item in alpine_evidence(index.get(cve, []))]
        else:
            raise ValueError("Unsupported vendor")
        return result, dict(url=url, checked=int(self.clock() * 1000), mode="API cache", **metadata)
