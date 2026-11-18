"""SQLite cache with shared workspace watches and unwatched-case retention."""

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

RETENTION = 10 * 24 * 3600
RETENTION_DAYS = RETENTION // 86400


def _baseline(db, now):
    """Schema 1: the original tables plus workspace activity, inventory, statistics and metadata tables."""
    for statement in (
        "CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, payload TEXT NOT NULL, families TEXT NOT NULL,"
        " unwatched_since REAL, attempted REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS cases_unwatched ON cases(unwatched_since)",
        "CREATE TABLE IF NOT EXISTS watches (workspace TEXT NOT NULL, id TEXT NOT NULL, families TEXT NOT NULL,"
        " PRIMARY KEY (workspace, id))",
        "CREATE INDEX IF NOT EXISTS watches_case ON watches(id)",
        "CREATE TABLE IF NOT EXISTS agents (filename TEXT PRIMARY KEY, product TEXT, payload TEXT, seen REAL)",
        "CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, last_seen REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS workspaces_seen ON workspaces(last_seen)",
        "CREATE TABLE IF NOT EXISTS ksp_platforms (product TEXT NOT NULL, arch TEXT NOT NULL, package TEXT,"
        " first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (product, arch))",
        "CREATE TABLE IF NOT EXISTS ksp_kernels (product TEXT NOT NULL, arch TEXT NOT NULL, kernel TEXT NOT NULL,"
        " flavor TEXT NOT NULL, since TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL,"
        " partial INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (product, arch, kernel, flavor))",
        "CREATE INDEX IF NOT EXISTS ksp_kernels_seen ON ksp_kernels(last_seen)",
        "CREATE TABLE IF NOT EXISTS stats (hour INTEGER NOT NULL, name TEXT NOT NULL, count INTEGER NOT NULL,"
        " PRIMARY KEY (hour, name))",
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ):
        db.execute(statement)
    # Existing watches start their inactivity clock at the upgrade.
    db.execute("INSERT OR IGNORE INTO workspaces SELECT DISTINCT workspace, ? FROM watches", (now,))


_SAFE_ERROR = re.compile(
    r"^(HTTP \d{3} from [\w.-]+|request timed out|connection failed \([\w.-]+\)|DNS lookup failed|TLS error"
    r"|response too large|invalid data from source|unexpected error|temporarily paused after repeated failures.*)$"
)


def _sanitize_errors(db, now):
    """Schema 2: earlier versions stored raw exception text in source errors; keep only the short categories."""

    def clean(message):
        prefix, _, detail = message.partition(": ")
        return message if _SAFE_ERROR.match(detail) else f"{prefix}: invalid data from source"

    # Page through the cases by primary key, so a large cache is never decoded at once.
    last = ""
    while rows := db.execute("SELECT id, payload FROM cases WHERE id > ? ORDER BY id LIMIT 100", (last,)).fetchall():
        for cve, text in rows:
            payload = json.loads(text)
            holders = [payload, *payload.get("vendorData", {}).get("sources", {}).values()]
            changed = False
            for holder in holders:
                if isinstance(holder.get("error"), str) and clean(holder["error"]) != holder["error"]:
                    holder["error"], changed = clean(holder["error"]), True
            if changed:
                db.execute("UPDATE cases SET payload=? WHERE id=?", (json.dumps(payload), cve))
        last = rows[-1][0]


def _ksp_membership(db, now):
    """Schema 3: KSP rows record whether they are in the latest page snapshot (``listed``) and, separately from the
    first release a kernel was listed in (``since``), the first release that listed it with full support."""
    for statement in (
        "ALTER TABLE ksp_platforms ADD COLUMN listed INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE ksp_kernels ADD COLUMN listed INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE ksp_kernels ADD COLUMN full_seen INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE ksp_kernels ADD COLUMN full_since TEXT",
        # Every store wrote one timestamp to all rows of a snapshot.
        "UPDATE ksp_platforms SET listed = (last_seen = (SELECT MAX(last_seen) FROM ksp_platforms))",
        "UPDATE ksp_kernels SET listed = EXISTS (SELECT 1 FROM ksp_platforms p WHERE p.product = ksp_kernels.product"
        " AND p.arch = ksp_kernels.arch AND p.listed AND p.last_seen = ksp_kernels.last_seen)",
        "UPDATE ksp_kernels SET full_seen = 1, full_since = since WHERE partial = 0",
    ):
        db.execute(statement)


# Append new steps; never change what a released one does. PRAGMA user_version records the applied count.
MIGRATIONS = [_baseline, _sanitize_errors, _ksp_membership]


class CapacityError(Exception):
    """A watch-list replacement would exceed a configured cap (``status`` is the HTTP status to answer with)."""

    def __init__(self, status, detail):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Cache:
    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.migrate(clock())

    def migrate(self, now):
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        isolation, self.db.isolation_level = self.db.isolation_level, None
        try:
            for target in range(version + 1, len(MIGRATIONS) + 1):
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    MIGRATIONS[target - 1](self.db, now)
                    self.db.execute(f"PRAGMA user_version={target}")
                    self.db.execute("COMMIT")
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise
        finally:
            self.db.isolation_level = isolation

    def prune(self, now):
        with self.db:
            self.db.execute("DELETE FROM cases WHERE unwatched_since <= ?", (now - RETENTION,))

    def get(self, cve):
        row = self.db.execute("SELECT * FROM cases WHERE id=?", (cve,)).fetchone()
        return (
            dict(
                payload=json.loads(row["payload"]),
                families=set(json.loads(row["families"])),
                unwatched_since=row["unwatched_since"],
                attempted=row["attempted"],
            )
            if row
            else None
        )

    def peek(self, cve):
        """Refresh bookkeeping of a case without decoding its payload."""
        row = self.db.execute("SELECT families, unwatched_since, attempted FROM cases WHERE id=?", (cve,)).fetchone()
        return (
            dict(families=set(json.loads(row[0])), unwatched_since=row["unwatched_since"], attempted=row["attempted"])
            if row
            else None
        )

    def put(self, cve, row):
        with self.db:
            self.db.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,"
                " families=excluded.families, attempted=excluded.attempted",
                (
                    cve,
                    json.dumps(row["payload"]),
                    json.dumps(sorted(row["families"])),
                    row["unwatched_since"],
                    row["attempted"],
                ),
            )

    def delete(self, cve):
        with self.db:
            self.db.execute("DELETE FROM cases WHERE id=?", (cve,))

    def watch_families(self, cve):
        rows = self.db.execute("SELECT families FROM watches WHERE id=?", (cve,))
        return {family for row in rows for family in json.loads(row[0])}

    def watched_ids(self):
        return [row[0] for row in self.db.execute("SELECT DISTINCT id FROM watches")]

    def watched(self, cve):
        return self.db.execute("SELECT 1 FROM watches WHERE id=? LIMIT 1", (cve,)).fetchone() is not None

    @contextmanager
    def transaction(self):
        """One write transaction (``BEGIN IMMEDIATE``): reads inside it see a stable state."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.rollback()
            raise
        self.db.commit()

    def _mark_watched(self, ids, now):
        """Start or end the unwatched-retention clock of ``ids`` according to the current watches (in a transaction)."""
        ids = json.dumps(sorted(ids))
        self.db.execute(
            "UPDATE cases SET unwatched_since = NULL WHERE id IN (SELECT value FROM json_each(?))"
            " AND id IN (SELECT id FROM watches)",
            (ids,),
        )
        self.db.execute(
            "UPDATE cases SET unwatched_since = COALESCE(unwatched_since, ?) WHERE id IN (SELECT value FROM json_each(?))"
            " AND id NOT IN (SELECT id FROM watches)",
            (now, ids),
        )

    def replace_watches(self, workspace, entries, now, limits=None):
        """Replace a workspace's watch list in one transaction, checking ``limits`` against the result.

        ``limits`` maps ``per_workspace``, ``watched_cves``, ``watch_rows`` and ``workspaces`` to caps. A cap only
        rejects a change that would raise its total above it, so reductions always pass, also when a cap was lowered
        below the current count. Raises ``CapacityError``.
        """
        with self.transaction() as db:
            previous = {row[0] for row in db.execute("SELECT id FROM watches WHERE workspace=?", (workspace,))}
            current = {entry["id"] for entry in entries}
            if limits:
                self._check_capacity(workspace, previous, current, limits)
            db.execute("DELETE FROM watches WHERE workspace=?", (workspace,))
            db.executemany(
                "INSERT INTO watches VALUES (?, ?, ?)",
                [(workspace, entry["id"], json.dumps(entry["families"])) for entry in entries],
            )
            if entries:
                db.execute(
                    "INSERT INTO workspaces VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
                    (workspace, now),
                )
            else:
                db.execute("DELETE FROM workspaces WHERE id=?", (workspace,))
            self._mark_watched(previous | current, now)

    def _check_capacity(self, workspace, previous, current, limits):
        one = self.db.execute
        if len(current) > limits["per_workspace"] and len(current) > len(previous):
            raise CapacityError(
                422, f"A workspace can watch at most {limits['per_workspace']} cases. Archive or delete some."
            )
        shared = {
            row[0]
            for row in one(
                "SELECT DISTINCT w.id FROM watches w JOIN json_each(?) j ON w.id = j.value WHERE w.workspace != ?",
                (json.dumps(sorted(previous | current)), workspace),
            )
        }
        rows = one("SELECT COUNT(*) FROM watches").fetchone()[0]
        distinct = one("SELECT COUNT(DISTINCT id) FROM watches").fetchone()[0]
        workspaces = one("SELECT COUNT(*) FROM workspaces").fetchone()[0]
        known = one("SELECT 1 FROM workspaces WHERE id=?", (workspace,)).fetchone() is not None
        totals = {
            "watched_cves": (distinct, distinct - len(previous - shared) + len(current - shared)),
            "watch_rows": (rows, rows - len(previous) + len(current)),
            "workspaces": (workspaces, workspaces + (bool(current) and not known) - (not current and known)),
        }
        for name, (before, after) in totals.items():
            if after > limits[name] and after > before:
                raise CapacityError(429, "Watch capacity reached")

    def sync_watches(self, workspace, entries, now):
        self.replace_watches(workspace, entries, now)

    def prune_workspaces(self, cutoff, now, batch=500):
        """Drop up to ``batch`` workspaces not seen since ``cutoff``; their watches end and the retention clock starts.

        Returns the number removed; the caller repeats on later ticks while there are more.
        """
        with self.transaction() as db:
            stale = [
                row[0]
                for row in db.execute(
                    "SELECT id FROM workspaces WHERE last_seen <= ? ORDER BY last_seen LIMIT ?", (cutoff, batch)
                )
            ]
            if len(stale) < batch:
                # Watches without a workspace row cannot be renewed (e.g. written before the row existed).
                stale += [
                    row[0]
                    for row in db.execute(
                        "SELECT DISTINCT workspace FROM watches WHERE workspace NOT IN (SELECT id FROM workspaces)"
                        " LIMIT ?",
                        (batch - len(stale),),
                    )
                ]
            if not stale:
                return 0
            selected = json.dumps(stale)
            affected = [
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT id FROM watches WHERE workspace IN (SELECT value FROM json_each(?))", (selected,)
                )
            ]
            db.execute("DELETE FROM watches WHERE workspace IN (SELECT value FROM json_each(?))", (selected,))
            db.execute("DELETE FROM workspaces WHERE id IN (SELECT value FROM json_each(?))", (selected,))
            self._mark_watched(affected, now)
        return len(stale)

    def watched_cases(self):
        """``(cve, watched families, covered families or None, last full refresh or None)`` for every watched CVE,
        least recently refreshed first (never fetched ones first)."""
        rows = self.db.execute(
            "SELECT w.id, json_group_array(json(w.families)), c.families, c.attempted FROM watches w"
            " LEFT JOIN cases c ON c.id = w.id GROUP BY w.id ORDER BY COALESCE(c.attempted, 0), w.id"
        )
        return [
            (
                cve,
                {family for families in json.loads(watched) for family in families},
                set(json.loads(covered)) if covered is not None else None,
                attempted,
            )
            for cve, watched, covered, attempted in rows
        ]

    def counts(self):
        one = self.db.execute
        return {
            "cachedCves": one("SELECT COUNT(*) FROM cases").fetchone()[0],
            "watchedCves": one("SELECT COUNT(DISTINCT id) FROM watches").fetchone()[0],
            "workspaces": one("SELECT COUNT(*) FROM workspaces").fetchone()[0],
        }

    def get_meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        with self.db:
            self.db.execute(
                "INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )

    def ids(self):
        return [row[0] for row in self.db.execute("SELECT id FROM cases ORDER BY attempted")]

    def close(self):
        self.db.close()
