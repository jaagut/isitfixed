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
        """Counter totals over the most recent ``hours`` buckets, including the current partial hour."""
        start = int(self.clock() // HOUR) - hours + 1
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

    def hourly(self, hours=24):
        """Contiguous UTC buckets for charts, including counters awaiting their next flush."""
        end = int(self.clock() // HOUR)
        start = end - hours + 1
        buckets = {hour: Counter() for hour in range(start, end + 1)}
        for hour, name, count in self.cache.db.execute(
            "SELECT hour, name, count FROM stats WHERE hour BETWEEN ? AND ?", (start, end)
        ):
            buckets[hour][name] += count
        for (hour, name), count in self.pending.items():
            if hour in buckets:
                buckets[hour][name] += count
        return [
            {
                "hourUtc": hour * HOUR,
                "refreshes": sum(n for key, n in counts.items() if key.startswith("refresh.")),
                "fetches": sum(n for key, n in counts.items() if key.startswith("fetch.")),
                "failures": sum(n for key, n in counts.items() if key.startswith("failure.")),
                "rateLimited": sum(n for key, n in counts.items() if key.startswith("ratelimited.")),
            }
            for hour, counts in buckets.items()
        ]

    def windows(self):
        return {label: self.totals(hours) for label, hours in WINDOWS.items()}
