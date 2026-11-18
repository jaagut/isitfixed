"""Hourly inventory of Deep Security 20.0 Kernel Support Packages (KSP) from Trend Micro's public kernel list."""

import asyncio
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .cache import RETENTION
from .fetch import MIB, read_limited
from .jobs import HourlyJob

PAGE = (
    "https://files.trendmicro.com/documentation/guides/deep_security/Kernel%20Support/20.0/"
    "Deep_Security_20_0_kernels_EN.html"
)
PAGE_LIMIT = 32 * MIB
PAGE_DEADLINE = 120
DOWNLOAD_PREFIX = "/products/deepsecurity/en/20.0/"
# Page platform names → product ids used by the frontend.
PRODUCTS = {
    **{f"rhel{v}": f"rhel{v}" for v in (8, 9, 10)},
    **{f"suse{v}": f"sles{v}" for v in (15, 16)},
    **{f"debian{v}": f"debian{v}" for v in (12, 13)},
    **{f"ubuntu{v}": f"ubuntu{v}04" for v in (20, 22, 24, 26)},
}
ARCHITECTURES = {"64": "x86_64", "32": "i386", "aarch64": "aarch64", "ppc64le": "ppc64le", "s390x": "s390x"}
HEADING = re.compile(r"^(?P<platform>[a-z]+\d+)\s*\((?P<arch>[a-z0-9_]+)-bit\)$", re.I)
FILENAME = re.compile(
    r"KernelSupport-(?P<stream>[A-Za-z0-9_.]+?)-(?P<release>\d+\.\d+\.\d+-\d+)\.(?P<arch>[A-Za-z0-9_]+)\.zip"
)
KERNEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{2,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UPDATED = re.compile(r"\(([^()]*\d{4}[^()]*)\)\s*$")
REQUIREMENT = re.compile(
    r"To use KSP 20\.0\.1\b.*?DSM version is (?P<dsm>[\w.-]+?)[,.]? or later.*?DSA version is (?P<dsa>[\w.-]+?)[,.]? or later",
    re.I,
)
PARTIAL_MARK = "Δ"  # Δ: only WRS/FW/IPS features are supported by the latest KSP


def _clean(parts):
    return " ".join("".join(parts).split())


class _PageParser(HTMLParser):
    """Collects headings, tables (header, rows of cells with text/links/id) and text lines outside tables."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.h1 = None
        self.heading = None
        self.tables, self.lines = [], []
        self._heading_tag, self._heading_text = None, []
        self._table = self._row = self._cell = None
        self._depth = 0
        self._line = []

    def _end_cell(self):
        if self._cell is not None and self._row is not None:
            self._row.append({**self._cell, "text": _clean(self._cell["text"])})
        self._cell = None

    def _end_row(self):
        self._end_cell()
        if self._row and self._table is not None:
            if all(cell["tag"] == "th" for cell in self._row) and not self._table["header"]:
                self._table["header"] = [cell["text"] for cell in self._row]
            else:
                self._table["rows"].append(self._row)
        self._row = None

    def _end_line(self):
        if line := _clean(self._line):
            self.lines.append(line)
        self._line = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._depth += 1
            if self._depth == 1:
                self._end_line()
                self._table = {"heading": self.heading, "header": [], "rows": []}
            return
        if self._depth == 1:
            if tag == "tr":
                self._end_row()
                self._row = []
            elif tag in ("td", "th"):
                self._end_cell()
                if self._row is None:
                    self._row = []
                self._cell = {"tag": tag, "text": [], "links": [], "id": dict(attrs).get("id") or ""}
            elif tag == "a" and self._cell is not None and (href := dict(attrs).get("href")):
                self._cell["links"].append(href)
            return
        if self._depth:
            return
        if tag in ("h1", "h2", "h3"):
            self._end_line()
            self._heading_tag, self._heading_text = tag, []
        elif tag in ("br", "p", "li", "div", "h4", "h5"):
            self._end_line()

    def handle_endtag(self, tag):
        if tag == "table" and self._depth:
            self._depth -= 1
            if self._depth == 0 and self._table is not None:
                self._end_row()
                self.tables.append(self._table)
                self._table = None
            return
        if self._depth == 1:
            if tag in ("td", "th"):
                self._end_cell()
            elif tag == "tr":
                self._end_row()
            return
        if self._depth:
            return
        if tag == self._heading_tag:
            text = _clean(self._heading_text)
            if tag == "h1":
                self.h1 = self.h1 or text
            else:
                self.heading = text
            self._heading_tag = None
        elif tag in ("p", "li", "div", "h4", "h5"):
            self._end_line()

    def handle_data(self, data):
        if self._depth:
            if self._cell is not None:
                self._cell["text"].append(data)
            return
        if self._heading_tag:
            self._heading_text.append(data)
        self._line.append(data)

    def close(self):
        super().close()
        self._end_line()


@dataclass
class Platform:
    package: dict | None = None
    kernels: list[tuple[str, str, bool]] = field(default_factory=list)


@dataclass
class Page:
    updated: str | None
    notes: list[str]
    platforms: dict[tuple[str, str], Platform]


def _download(href, filename):
    parts = urlsplit(href or "")
    if parts.hostname == "files.trendmicro.com" and parts.path == DOWNLOAD_PREFIX + filename:
        return f"https://files.trendmicro.com{parts.path}"
    return None


def _column(header, needle, default):
    return next((i for i, text in enumerate(header) if needle in text.lower()), default)


def _packages(table, platforms):
    header = table["header"]
    columns = (
        _column(header, "platform", 0),
        _column(header, "32/64", 1),
        _column(header, "kernel support package", 2),
        _column(header, "sha256", 3),
    )
    for row in table["rows"]:
        if len(row) <= max(columns):
            continue
        name, bits, package, digest = (row[i] for i in columns)
        product = PRODUCTS.get(name["text"].lower())
        match = FILENAME.search(package["text"]) or next(
            (m for link in package["links"] if (m := FILENAME.search(link))), None
        )
        if not product or not match:
            continue
        arch = match["arch"] if match["arch"] in ARCHITECTURES.values() else ARCHITECTURES.get(bits["text"])
        if not arch:
            continue
        filename = match[0]
        sha = digest["text"].lower()
        platforms.setdefault((product, arch), Platform()).package = {
            "filename": filename,
            "release": match["release"],
            "download": next((url for link in package["links"] if (url := _download(link, filename))), None),
            "sha256": sha if SHA256.match(sha) else None,
        }


def _kernels(table, platforms):
    heading = HEADING.match(table["heading"] or "")
    if not heading:
        return
    product = PRODUCTS.get(heading["platform"].lower())
    arch = ARCHITECTURES.get(heading["arch"].lower())
    if not product or not arch:
        return
    flavors = table["header"][1:]
    entry = platforms.setdefault((product, arch), Platform())
    for row in table["rows"]:
        if not row or not KERNEL.match(row[0]["text"]):
            continue
        for index, cell in enumerate(row[1:]):
            mark = cell["text"]
            if not mark:
                continue
            flavor = flavors[index] if index < len(flavors) and flavors[index] else cell["id"]
            if flavor and (mark.startswith("Y") or PARTIAL_MARK in mark):
                entry.kernels.append((row[0]["text"], flavor, PARTIAL_MARK in mark))


def parse(html):
    """Parse the kernel list page; raise ``ValueError`` when its structure is not recognised."""
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    platforms = {}
    package_tables = [t for t in parser.tables if any("kernel support package" in h.lower() for h in t["header"])]
    for table in package_tables:
        _packages(table, platforms)
    for table in parser.tables:
        _kernels(table, platforms)
    if not package_tables or not any(p.kernels for p in platforms.values()):
        raise ValueError("Kernel support page has an unexpected structure")
    updated = UPDATED.search(parser.h1 or "")
    notes = []
    for line in parser.lines:
        if match := REQUIREMENT.search(line):
            notes.append(f"To use KSP 20.0.1 or later, DSM {match['dsm']}+ and DSA {match['dsa']}+ are required.")
            break
    return Page(updated[1].strip() if updated else None, notes, platforms)


class KernelSupport(HourlyJob):
    """Stores the current KSP per product/architecture and every listed kernel with the KSP it first appeared in.

    ``since`` is the KSP release that was current when this server first saw a kernel listed, or null when the
    kernel was already listed the first time this server observed that product/architecture.
    """

    name = "tmds-ksp"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._snapshot, self._built = None, None

    async def run(self):
        data = await read_limited(self.client, PAGE, limit=PAGE_LIMIT, deadline=PAGE_DEADLINE)
        page = await asyncio.to_thread(parse, data)
        self.store(page, self.clock())

    def store(self, page, now):
        db = self.cache.db
        with db:
            for (product, arch), platform in sorted(page.platforms.items()):
                known = db.execute("SELECT 1 FROM ksp_platforms WHERE product=? AND arch=?", (product, arch)).fetchone()
                package = json.dumps(platform.package) if platform.package else None
                db.execute(
                    "INSERT INTO ksp_platforms VALUES (?, ?, ?, ?, ?) ON CONFLICT(product, arch) DO UPDATE SET"
                    " package=COALESCE(excluded.package, package), last_seen=excluded.last_seen",
                    (product, arch, package, now, now),
                )
                current = db.execute(
                    "SELECT package FROM ksp_platforms WHERE product=? AND arch=?", (product, arch)
                ).fetchone()[0]
                since = json.loads(current)["release"] if known and current else None
                db.executemany(
                    "INSERT INTO ksp_kernels VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(product, arch, kernel, flavor) DO UPDATE SET"
                    " last_seen=excluded.last_seen, partial=excluded.partial",
                    [
                        (product, arch, kernel, flavor, since, now, now, int(partial))
                        for kernel, flavor, partial in platform.kernels
                    ],
                )
        self.extra = {"pageUpdated": page.updated, "notes": page.notes}
        self._snapshot = None

    def cleanup(self):
        cutoff = self.clock() - RETENTION
        with self.cache.db:
            self.cache.db.execute("DELETE FROM ksp_kernels WHERE last_seen <= ?", (cutoff,))
            self.cache.db.execute("DELETE FROM ksp_platforms WHERE last_seen <= ?", (cutoff,))
        self._snapshot = None

    def products(self):
        # The full list is a few hundred KB; rebuild it at most once a minute or after an update.
        minute = int(self.clock() // 60)
        if self._snapshot is not None and self._built == minute:
            return self._snapshot
        cutoff = self.clock() - RETENTION
        db = self.cache.db
        products = {}
        entries = {}
        for row in db.execute(
            "SELECT product, arch, package FROM ksp_platforms WHERE last_seen > ? ORDER BY product, arch", (cutoff,)
        ):
            package = json.loads(row["package"]) if row["package"] else {}
            entry = {
                "architecture": row["arch"],
                "platform": row["product"],
                **{key: package.get(key) for key in ("filename", "release", "download", "sha256")},
                "kernels": [],
            }
            entries[(row["product"], row["arch"])] = entry
            products.setdefault(row["product"], []).append(entry)
        for row in db.execute(
            "SELECT product, arch, kernel, flavor, since, partial FROM ksp_kernels WHERE last_seen > ?"
            " ORDER BY product, arch, first_seen, rowid",
            (cutoff,),
        ):
            if entry := entries.get((row["product"], row["arch"])):
                entry["kernels"].append([row["kernel"], row["flavor"], row["since"], bool(row["partial"])])
        self._snapshot, self._built = products, minute
        return products

    def snapshot(self):
        return {
            "products": self.products(),
            **self.status(),
            "source": PAGE,
            "pageUpdated": self.extra.get("pageUpdated"),
            "notes": self.extra.get("notes", []),
        }

    def counts(self):
        one = self.cache.db.execute
        cutoff = self.clock() - RETENTION
        return {
            "platforms": one("SELECT COUNT(*) FROM ksp_platforms WHERE last_seen > ?", (cutoff,)).fetchone()[0],
            "kernels": one("SELECT COUNT(*) FROM ksp_kernels WHERE last_seen > ?", (cutoff,)).fetchone()[0],
        }
