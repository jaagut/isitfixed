"""Anonymous operational counters in hourly buckets (no IPs, workspace ids or CVE-to-workspace links)."""

import time
from collections import Counter

HOUR = 3600
STATS_RETENTION_HOURS = 14 * 24
WINDOWS = {"1h": 1, "24h": 24, "14d": STATS_RETENTION_HOURS}
REFRESH_KINDS = ("scheduled", "on_demand", "manual")


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

    def _buckets(self, start, end, width):
        """Counters for hours ``start..end`` (inclusive), grouped into buckets of ``width`` hours."""
        buckets = {hour // width: Counter() for hour in range(start, end + 1)}
        for hour, name, count in self.cache.db.execute(
            "SELECT hour, name, count FROM stats WHERE hour BETWEEN ? AND ?", (start, end)
        ):
            buckets[hour // width][name] += count
        for (hour, name), count in self.pending.items():
            if start <= hour <= end:
                buckets[hour // width][name] += count
        return buckets

    @staticmethod
    def _summary(counts):
        def total(prefix):
            return sum(n for key, n in counts.items() if key.startswith(prefix))

        return {
            "refreshes": total("refresh."),
            "fetches": total("fetch."),
            "failures": total("failure."),
            "rateLimited": total("ratelimited."),
            "refreshKinds": {kind: counts[f"refresh.{kind}"] for kind in REFRESH_KINDS},
        }

    def hourly(self, hours=24):
        """Contiguous UTC buckets for charts, including counters awaiting their next flush."""
        end = int(self.clock() // HOUR)
        buckets = self._buckets(end - hours + 1, end, 1)
        return [{"hourUtc": hour * HOUR, **self._summary(counts)} for hour, counts in buckets.items()]

    def daily(self, days=STATS_RETENTION_HOURS // 24):
        """Contiguous UTC calendar days (the oldest one may be partly expired, the current one is partial)."""
        end = int(self.clock() // HOUR)
        today = end // 24
        buckets = self._buckets(max((today - days + 1) * 24, end - STATS_RETENTION_HOURS + 1), end, 24)
        return [{"dayUtc": day * 24 * HOUR, **self._summary(counts)} for day, counts in buckets.items()]

    def windows(self):
        return {label: self.totals(hours) for label, hours in WINDOWS.items()}
