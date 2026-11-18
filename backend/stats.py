"""Anonymous operational counters in hourly buckets (no IPs, workspace ids or CVE-to-workspace links)."""

import time
from collections import Counter

HOUR = 3600
STATS_RETENTION_HOURS = 14 * 24
WINDOWS = {"1h": 1, "24h": 24, "14d": STATS_RETENTION_HOURS}


class Stats:
    def __init__(self, cache, clock=time.time):
        self.cache, self.clock = cache, clock
        self.started = clock()
        self.pending: Counter[tuple[int, str]] = Counter()

    def incr(self, name, count=1):
        self.pending[(int(self.clock() // HOUR), name)] += count

    def flush(self):
        """Persist pending counters and drop buckets older than 14 days."""
        current = int(self.clock() // HOUR)
        with self.cache.db:
            self.cache.db.executemany(
                "INSERT INTO stats VALUES (?, ?, ?) ON CONFLICT(hour, name) DO UPDATE SET count=count+excluded.count",
                [(hour, name, count) for (hour, name), count in self.pending.items()],
            )
            self.cache.db.execute("DELETE FROM stats WHERE hour <= ?", (current - STATS_RETENTION_HOURS,))
        self.pending.clear()

    def totals(self, hours):
        """Counter totals over the current hour bucket plus the ``hours`` preceding buckets."""
        start = int(self.clock() // HOUR) - hours
        totals = Counter(
            {
                row[0]: row[1]
                for row in self.cache.db.execute(
                    "SELECT name, SUM(count) FROM stats WHERE hour >= ? GROUP BY name", (start,)
                )
            }
        )
        for (hour, name), count in self.pending.items():
            if hour >= start:
                totals[name] += count
        return totals

    def windows(self):
        return {label: self.totals(hours) for label, hours in WINDOWS.items()}
