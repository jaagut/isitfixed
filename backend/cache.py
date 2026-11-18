"""SQLite cache with shared workspace watches and unwatched-case retention."""

import json
import sqlite3
from pathlib import Path

RETENTION = 10 * 24 * 3600


class Cache:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, payload TEXT NOT NULL, families TEXT NOT NULL, unwatched_since REAL, attempted REAL NOT NULL)"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS cases_unwatched ON cases(unwatched_since)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS watches (workspace TEXT NOT NULL, id TEXT NOT NULL, families TEXT NOT NULL, PRIMARY KEY (workspace, id))"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS watches_case ON watches(id)")
        self.db.commit()

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

    def put(self, cve, row):
        with self.db:
            self.db.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, families=excluded.families, attempted=excluded.attempted",
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

    def sync_watches(self, workspace, entries, now):
        previous = {row[0] for row in self.db.execute("SELECT id FROM watches WHERE workspace=?", (workspace,))}
        current = {entry["id"] for entry in entries}
        with self.db:
            self.db.execute("DELETE FROM watches WHERE workspace=?", (workspace,))
            self.db.executemany(
                "INSERT INTO watches VALUES (?, ?, ?)",
                [(workspace, entry["id"], json.dumps(entry["families"])) for entry in entries],
            )
            for cve in previous | current:
                if self.watched(cve):
                    self.db.execute("UPDATE cases SET unwatched_since=NULL WHERE id=?", (cve,))
                else:
                    self.db.execute(
                        "UPDATE cases SET unwatched_since=COALESCE(unwatched_since, ?) WHERE id=?", (now, cve)
                    )

    def ids(self):
        return [row[0] for row in self.db.execute("SELECT id FROM cases ORDER BY attempted")]

    def close(self):
        self.db.close()
