"""Private admin dashboard (separate port): anonymous operational statistics, no IPs or workspace ids."""

import base64
import binascii
import hmac
import html
import os
import resource
import shutil
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .main import STALL_AFTER
from .security import SecurityHeaders
from .stats import REFRESH_KINDS, WINDOWS

SOURCES = ("record", "rhel", "sles", "ubuntu", "debian", "alpine", "tmds-agents", "tmds-ksp")
STYLESHEET = Path(__file__).with_name("admin.css")


def _read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _number(text):
    return int(text) if text and text.isdigit() else None


class ProcessSampler:
    """CPU usage between two dashboard requests (since process start for the first one)."""

    def __init__(self):
        times = os.times()
        self.wall, self.cpu = time.monotonic(), times.user + times.system

    def sample(self):
        times = os.times()
        wall, cpu = time.monotonic(), times.user + times.system
        elapsed = wall - self.wall
        percent = round(100 * (cpu - self.cpu) / elapsed, 1) if elapsed > 0 else None
        self.wall, self.cpu = wall, cpu
        rss = None
        status = _read("/proc/self/status") or ""
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1]) * 1024
        if rss is None:  # Peak RSS where /proc is unavailable (kilobytes on Linux).
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        return {"rssBytes": rss, "cpuPercent": percent, "cpuSeconds": round(cpu, 1)}


def container_cpu_cores():
    """CPU cores available to the container: the cgroup quota if set, otherwise the visible CPUs."""
    quota, _, period = (_read("/sys/fs/cgroup/cpu.max") or "").partition(" ")
    if quota.isdigit() and period.isdigit() and int(period):
        return round(int(quota) / int(period), 2)
    return len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()


def host_memory():
    for line in (_read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return None


def container_memory():
    return {
        "memoryBytes": _number(_read("/sys/fs/cgroup/memory.current")),
        "memoryLimitBytes": _number(_read("/sys/fs/cgroup/memory.max")),  # "max" (unlimited) → null
        "cpuCores": container_cpu_cores(),
        "hostMemoryBytes": host_memory(),
    }


def storage(database, log_dir):
    result = {"databaseBytes": None, "dataDisk": None, "logBytes": None}
    try:
        result["databaseBytes"] = sum(
            path.stat().st_size for path in database.parent.glob(database.name + "*") if path.is_file()
        )
        usage = shutil.disk_usage(database.parent)
        result["dataDisk"] = {"totalBytes": usage.total, "usedBytes": usage.used, "freeBytes": usage.free}
    except OSError:
        pass
    if log_dir:
        try:
            result["logBytes"] = sum(path.stat().st_size for path in Path(log_dir).iterdir() if path.is_file())
        except OSError:
            pass
    return result


def collect(state, sampler):
    """All dashboard numbers from the public app's state."""
    settings, stats = state.settings, state.stats
    now = time.time()
    windows = stats.windows()
    breaker = state.breaker.snapshot()
    workers = {
        name: (round(time.monotonic() - owner.beat, 1) if owner.beat is not None else None, task.done())
        for name, (owner, task) in state.workers.items()
    }
    return {
        "version": settings.version,
        "hourly": stats.hourly(),
        "daily": stats.daily(),
        "startedAt": int(state.started * 1000),
        "uptimeSeconds": int(now - state.started),
        "flags": {
            "manualRefresh": settings.manual_refresh,
            "tmds": settings.tmds_enabled,
            "apiDocs": settings.api_docs,
            "hsts": settings.hsts,
            "adminToken": bool(settings.admin_token),
            "logFiles": bool(settings.log_dir),
            "legal": state.legal.enabled(),
        },
        "limits": {
            "maxWatchedCves": settings.max_watched_cves,
            "maxCachedCves": settings.max_cached_cves,
            "maxWatchesPerWorkspace": settings.max_watches_per_workspace,
            "workspaceTtlDays": settings.workspace_ttl_days,
            "rateLimitsPerMinute": {
                "requests": settings.rate_limit_requests,
                "lookups": settings.rate_limit_lookups,
                "lookupsGlobal": settings.rate_limit_lookups_global,
                "watches": settings.rate_limit_watches,
            },
        },
        "data": state.cache.counts(),
        "refreshes": {w: {kind: totals[f"refresh.{kind}"] for kind in REFRESH_KINDS} for w, totals in windows.items()},
        "sources": {
            name: {
                "fetches": {w: totals[f"fetch.{name}"] for w, totals in windows.items()},
                "failures": {w: totals[f"failure.{name}"] for w, totals in windows.items()},
                **breaker.get(
                    name,
                    {
                        "consecutiveFailures": 0,
                        "pausedUntil": None,
                        "lastError": None,
                        "lastErrorAt": None,
                        "lastSuccessAt": None,
                    },
                ),
            }
            for name in SOURCES
        },
        "rateLimited": {
            w: {
                name.removeprefix("ratelimited."): count
                for name, count in totals.items()
                if name.startswith("ratelimited.")
            }
            for w, totals in windows.items()
        },
        "capacityRejected": {
            w: {kind: totals[f"capacity.{kind}"] for kind in ("workspace", "server")} for w, totals in windows.items()
        },
        "tmds": {
            "enabled": settings.tmds_enabled,
            "agents": {**state.inventory.status(), **state.inventory.counts()},
            "ksp": {
                **state.ksp.status(),
                **state.ksp.counts(),
                "pageUpdated": state.ksp.extra.get("pageUpdated"),
            },
        },
        "process": sampler.sample(),
        "container": container_memory(),
        "storage": storage(state.cache.path, settings.log_dir),
        "workers": {
            name: {
                "heartbeatAgeSeconds": age,
                "stopped": done,
                "stallAfterSeconds": STALL_AFTER[name],
                "stalled": done or (age is not None and age > STALL_AFTER[name]),
            }
            for name, (age, done) in workers.items()
        },
    }


# ---------------------------------------------------------------- Rendering (server-side HTML, inline SVG, no JS)

SOURCE_LABELS = {
    "record": "CVE record",
    "rhel": "Red Hat",
    "sles": "SUSE",
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "alpine": "Alpine",
    "tmds-agents": "TMDS agents",
    "tmds-ksp": "TMDS KSP",
}
WORKER_LABELS = {
    "refresh": "Case refresh",
    "maintenance": "Maintenance",
    "tmds-agents": "TMDS agent feed",
    "tmds-ksp": "TMDS kernel support",
}
KIND_LABELS = {"scheduled": "Scheduled", "on_demand": "On demand", "manual": "Manual"}
BUDGETS = (
    ("requests", "All API requests", "requests"),
    ("lookups", "Case lookups per client", "lookups"),
    ("lookups-global", "Case lookups, all clients", "lookupsGlobal"),
    ("watches", "Watch list updates", "watches"),
)
CHART_WIDTH, CHART_HEIGHT = 288, 100


def _e(value):
    return html.escape(str(value), quote=True)


def _n(value):
    return "–" if value is None else f"{value:,}"


def _size(value):
    if value is None:
        return "–"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _time(ms):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ms / 1000)) if ms else "–"


def _span(seconds):
    """A compact human duration: 42 s, 7 min, 3 h 20 min, 5 d 2 h."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}\u00a0s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}\u00a0min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}\u00a0h {minutes}\u00a0min" if minutes and hours < 10 else f"{hours}\u00a0h"
    days, hours = divmod(hours, 24)
    return f"{days}\u00a0d {hours}\u00a0h" if hours else f"{days}\u00a0d"


def _when(ms, now, future=False):
    """A <time> element with a relative label and the absolute UTC time as tooltip."""
    if not ms:
        return "never"
    delta = (ms / 1000 - now) if future else (now - ms / 1000)
    label = (
        ("in " + _span(delta) if delta >= 1 else "now")
        if future
        else (_span(delta) + " ago" if delta >= 60 else "just now")
    )
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))
    return f"<time datetime='{iso}' title='{_time(ms)}'>{label}</time>"


def _percent(part, whole):
    return round(100 * part / whole) if whole else None


def _meter(value, maximum, label, low=0.7, high=0.9):
    """A native <meter>: the browser colours it optimum/suboptimal/critical from the thresholds."""
    maximum = max(maximum, 1e-9)
    value = min(max(value, 0), maximum)
    return (
        f"<meter min='0' max='{maximum:g}' low='{maximum * low:g}' high='{maximum * high:g}' optimum='0'"
        f" value='{value:g}' aria-label='{_e(label)}'></meter>"
    )


def _chip(tone, text):
    return f"<span class='chip {tone}'><span class='dot' aria-hidden='true'></span>{_e(text)}</span>"


def _sparkline(values, label):
    """A 24-hour area sparkline that stretches to its card (strokes stay crisp via non-scaling-stroke)."""
    width, height = 120, 32
    peak = max(values, default=0)
    if not peak:
        return (
            f"<svg class='spark flat' viewBox='0 0 {width} {height}' preserveAspectRatio='none' role='img'"
            f" aria-label='{_e(label)}: no events in the last 24 hours'>"
            f"<line x1='0' y1='{height - 1}' x2='{width}' y2='{height - 1}' vector-effect='non-scaling-stroke'/></svg>"
        )
    step = width / max(len(values) - 1, 1)
    points = [(i * step, height - 1.5 - (height - 5) * value / peak) for i, value in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return (
        f"<svg class='spark' viewBox='0 0 {width} {height}' preserveAspectRatio='none' role='img'"
        f" aria-label='{_e(label)} per hour over the last 24 hours, peak {peak:,}'>"
        f"<polygon class='area' points='0,{height} {line} {width},{height}'/>"
        f"<polyline points='{line}' vector-effect='non-scaling-stroke'/></svg>"
    )


def _nice(peak):
    """A round axis maximum at or above ``peak`` whose half is a whole number."""
    if peak <= 10:
        return max(2, peak + peak % 2)
    magnitude = 10 ** (len(str(int(peak))) - 1)
    for step in (1, 2, 4, 5, 6, 8, 10):
        if step * magnitude >= peak:
            return step * magnitude
    return 10 * magnitude


def _bar_chart(heading, period, columns, series, total_label):
    """A stacked bar chart. ``columns``: [(tick label or "", tooltip label, {series key: value})]."""
    count = len(columns)
    totals = [sum(values.get(key, 0) for key, _, _ in series) for _, _, values in columns]
    peak = max(totals, default=0)
    grand = sum(totals)
    top = _nice(peak) if peak else 0
    slot = CHART_WIDTH / count
    bar = slot * 0.7
    grid = "".join(
        f"<line class='grid' x1='0' x2='{CHART_WIDTH}' y1='{y:g}' y2='{y:g}' vector-effect='non-scaling-stroke'/>"
        for y in (0, CHART_HEIGHT / 2)
    )
    groups = []
    for i, ((_, tooltip, values), total) in enumerate(zip(columns, totals, strict=True)):
        if not total:
            continue
        x = i * slot + (slot - bar) / 2
        y = CHART_HEIGHT
        rects = []
        for key, _, css in series:
            value = values.get(key, 0)
            if value:
                h = CHART_HEIGHT * value / top
                y -= h
                rects.append(f"<rect class='{css}' x='{x:.2f}' y='{y:.2f}' width='{bar:.2f}' height='{h:.2f}'/>")
        parts = ", ".join(f"{name} {values.get(key, 0):,}" for key, name, _ in series if len(series) > 1)
        detail = f"{tooltip}: {total:,}" + (f" ({parts})" if parts else "")
        groups.append(
            f"<g><title>{_e(detail)}</title>"
            f"<rect class='hit' x='{i * slot:.2f}' y='0' width='{slot:.2f}' height='{CHART_HEIGHT}'/>"
            + "".join(rects)
            + "</g>"
        )
    summary = (
        f"{heading}, {period}: {grand:,} in total, peak {peak:,}."
        if peak
        else f"{heading}, {period}: no events recorded yet."
    )
    svg = (
        f"<svg viewBox='0 0 {CHART_WIDTH} {CHART_HEIGHT}' preserveAspectRatio='none' role='img'"
        f" aria-label='{_e(summary)}'>"
        f"{grid}{''.join(groups)}"
        f"<line class='base' x1='0' x2='{CHART_WIDTH}' y1='{CHART_HEIGHT}' y2='{CHART_HEIGHT}'"
        " vector-effect='non-scaling-stroke'/></svg>"
    )
    axis = (
        f"<div class='y' aria-hidden='true'><span>{top:,}</span><span>{top // 2:,}</span><span>0</span></div>"
        if peak
        else "<div class='y' aria-hidden='true'><span></span><span></span><span>0</span></div>"
    )
    ticks = "".join(f"<span>{_e(label)}</span>" for label, _, _ in columns)
    empty = "" if peak else "<p class='empty'>No data yet</p>"
    legend = ""
    if len(series) > 1:
        legend = (
            "<ul class='legend'>"
            + "".join(
                f"<li><span class='swatch {css}' aria-hidden='true'></span>{_e(name)}"
                f" <b>{sum(values.get(key, 0) for _, _, values in columns):,}</b></li>"
                for key, name, css in series
            )
            + "</ul>"
        )
    return (
        f"<figure class='chart'><figcaption><h3>{_e(heading)}</h3><span class='period'>{_e(period)}</span>"
        f"<strong class='total'>{grand:,}<small>{_e(total_label)}</small></strong></figcaption>{legend}"
        f"<div class='plot'>{axis}<div class='canvas'>{svg}{empty}</div>"
        f"<div class='x n{count}' aria-hidden='true'>{ticks}</div></div></figure>"
    )


def _hour_columns(rows, pick):
    columns = []
    for row in rows:
        hour = time.gmtime(row["hourUtc"])
        tick = time.strftime("%H:00", hour) if hour.tm_hour % 6 == 0 else ""
        columns.append((tick, time.strftime("%H:00–%H:59 UTC", hour), pick(row)))
    return columns


def _day_columns(rows, pick):
    columns = []
    for i, row in enumerate(rows):
        day = time.gmtime(row["dayUtc"])
        tick = "today" if i == len(rows) - 1 else str(day.tm_mday)
        columns.append((tick, time.strftime("%a %d %b UTC", day), pick(row)))
    return columns


def _health(data):
    """Overall state with a short reason: Stalled (a worker stopped or overdue) > Degraded > Healthy."""
    workers, sources = data["workers"], data["sources"]
    stalled = [WORKER_LABELS.get(name, name) for name, worker in workers.items() if worker["stalled"]]
    failing = [SOURCE_LABELS.get(name, name) for name, source in sources.items() if source["consecutiveFailures"]]
    if stalled:
        return "bad", "Stalled", ", ".join(stalled) + (" is" if len(stalled) == 1 else " are") + " not reporting"
    if failing:
        return "warn", "Degraded", ", ".join(failing) + (" is" if len(failing) == 1 else " are") + " failing"
    if not workers:
        return "ok", "Healthy", "Background jobs are disabled"
    return "ok", "Healthy", f"All {len(workers)} workers running, no upstream failures"


def _kpi(label, value, foot, visual="", tone=""):
    return (
        f"<article class='kpi {tone}'><h3>{_e(label)}</h3><p class='value'>{value}</p>"
        f"{visual}<p class='foot'>{foot}</p></article>"
    )


def _kpis(data):
    counts, limits, hourly = data["data"], data["limits"], data["hourly"]
    refreshes = {w: sum(kinds.values()) for w, kinds in data["refreshes"].items()}
    fetches = {w: sum(source["fetches"][w] for source in data["sources"].values()) for w in WINDOWS}
    failures = {w: sum(source["failures"][w] for source in data["sources"].values()) for w in WINDOWS}
    limited = {w: sum(counts_.values()) for w, counts_ in data["rateLimited"].items()}

    def capacity(value, limit, noun):
        share = _percent(value, limit)
        return _meter(value, limit, f"{share} % of the {noun} limit"), f"{share} % of {limit:,} limit"

    watched_meter, watched_foot = capacity(counts["watchedCves"], limits["maxWatchedCves"], "watched CVE")
    cached_meter, cached_foot = capacity(counts["cachedCves"], limits["maxCachedCves"], "cache")
    success = _percent(fetches["24h"] - failures["24h"], fetches["24h"])
    cards = [
        _kpi("Watched CVEs", _n(counts["watchedCves"]), watched_foot, watched_meter),
        _kpi("Cached CVEs", _n(counts["cachedCves"]), cached_foot, cached_meter),
        _kpi(
            "Workspaces",
            _n(counts["workspaces"]),
            f"Expire after {limits['workspaceTtlDays']} days idle · max {limits['maxWatchesPerWorkspace']:,} watches",
        ),
        _kpi(
            "Refreshes · 24 h",
            _n(refreshes["24h"]),
            f"{refreshes['1h']:,} in the last hour · {refreshes['14d']:,} in 14\u00a0d",
            _sparkline([row["refreshes"] for row in hourly], "Case refreshes"),
            "series-refresh",
        ),
        _kpi(
            "Upstream failures · 24 h",
            _n(failures["24h"]),
            f"of {fetches['24h']:,} fetches · {success} % succeeded" if fetches["24h"] else "No upstream fetches yet",
            _sparkline([row["failures"] for row in hourly], "Upstream failures"),
            "series-failure" + (" alert" if failures["24h"] else ""),
        ),
        _kpi(
            "Rate limited · 24 h",
            _n(limited["24h"]),
            f"HTTP 429 · {limited['1h']:,} in the last hour · {limited['14d']:,} in 14\u00a0d",
            _sparkline([row["rateLimited"] for row in hourly], "Rate-limited requests"),
            "series-limit" + (" alert" if limited["24h"] else ""),
        ),
    ]
    return (
        "<section class='kpis' aria-labelledby='kpis-title'><h2 id='kpis-title' class='sr-only'>Key figures</h2>"
        + "".join(cards)
        + "</section>"
    )


def _activity(data):
    hourly, daily = data["hourly"], data["daily"]
    kinds = [(kind, KIND_LABELS[kind], f"s-{kind.replace('_', '-')}") for kind in REFRESH_KINDS]
    fetch_series = [("ok", "Succeeded", "s-fetch-ok"), ("failed", "Failed", "s-fetch-failed")]

    def fetch_split(row):
        return {"ok": max(row["fetches"] - row["failures"], 0), "failed": row["failures"]}

    charts = [
        _bar_chart(
            "Case refreshes",
            "last 24 hours · per UTC hour",
            _hour_columns(hourly, lambda row: row["refreshKinds"]),
            kinds,
            "in 24 h",
        ),
        _bar_chart(
            "Case refreshes",
            "last 14 days · per UTC day",
            _day_columns(daily, lambda row: row["refreshKinds"]),
            kinds,
            "in 14 d",
        ),
        _bar_chart(
            "Upstream fetches",
            "last 24 hours · per UTC hour",
            _hour_columns(hourly, fetch_split),
            fetch_series,
            "in 24 h",
        ),
        _bar_chart(
            "Rate-limited requests",
            "last 24 hours · per UTC hour · HTTP 429",
            _hour_columns(hourly, lambda row: {"limited": row["rateLimited"]}),
            [("limited", "Rate limited", "s-limited")],
            "in 24 h",
        ),
    ]
    table = _table(
        ["Hour (UTC)", "Scheduled", "On demand", "Manual", "Fetches", "Failures", "Rate limited"],
        [
            [
                time.strftime("%H:00", time.gmtime(row["hourUtc"])),
                *(row["refreshKinds"][kind] for kind in REFRESH_KINDS),
                row["fetches"],
                row["failures"],
                row["rateLimited"],
            ]
            for row in reversed(hourly)
        ],
    )
    return (
        "<section class='panel activity' aria-labelledby='activity-title'>"
        "<div class='panel-head'><h2 id='activity-title'>Activity</h2>"
        "<p>Hover a bar for exact counts. The current hour and day are partial.</p></div>"
        f"<div class='charts'>{''.join(charts)}</div>"
        f"<details><summary>Hourly counts</summary><div class='scroll'>{table}</div></details></section>"
    )


def _table(headers, rows):
    """A table whose first column holds row headers and whose other columns are right-aligned figures."""
    head = "".join(f"<th scope='col'{'' if i == 0 else ' class=num'}>{_e(h)}</th>" for i, h in enumerate(headers))
    body = "".join(
        f"<tr><th scope='row'>{_e(row[0])}</th>"
        + "".join(f"<td class='num'>{_e(f'{c:,}' if isinstance(c, int) else c)}</td>" for c in row[1:])
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _source_state(source, now):
    if source["pausedUntil"]:
        return "warn", "Paused", f"Retrying {_when(source['pausedUntil'], now, future=True)}"
    if source["consecutiveFailures"]:
        failures = source["consecutiveFailures"]
        return "bad", "Failing", f"{failures} failure{'s' if failures != 1 else ''} in a row"
    if source["lastSuccessAt"]:
        return "ok", "OK", f"Last success {_when(source['lastSuccessAt'], now)}"
    if source["fetches"]["14d"]:
        return "ok", "OK", "No failures recorded"
    return "idle", "Idle", "No fetches yet"


def _sources(data, now):
    cards = []
    for name, source in data["sources"].items():
        tone, state, detail = _source_state(source, now)
        fetches, failures = source["fetches"]["24h"], source["failures"]["24h"]
        if fetches:
            rate = _percent(fetches - failures, fetches)
            ratio = (
                f"<meter class='ratio' min='0' max='100' low='90' high='99' optimum='100' value='{rate}'"
                f" aria-label='{rate} % of fetches succeeded in 24 hours'></meter>"
            )
        else:
            rate, ratio = (
                None,
                "<meter class='ratio' min='0' max='100' value='0' aria-label='No fetches in 24 hours'></meter>",
            )
        error = ""
        if source["lastError"]:
            error = (
                f"<p class='error'><span class='sr-only'>Last error: </span>{_e(source['lastError'])}"
                f" <span class='when'>{_when(source['lastErrorAt'], now)}</span></p>"
            )
        cards.append(
            f"<li class='source {tone}'><div class='source-head'><h3>{_e(SOURCE_LABELS.get(name, name))}"
            f" <code>{_e(name)}</code></h3>{_chip(tone, state)}</div>"
            f"<p class='detail'>{detail}</p>"
            f"<dl class='mini'><div><dt>Fetches 24 h</dt><dd>{fetches:,}</dd></div>"
            f"<div><dt>Failures 24 h</dt><dd>{failures:,}</dd></div>"
            f"<div><dt>Success</dt><dd>{'–' if rate is None else f'{rate} %'}</dd></div></dl>"
            f"{ratio}{error}</li>"
        )
    return (
        "<section class='panel sources' aria-labelledby='sources-title'><div class='panel-head'>"
        "<h2 id='sources-title'>Upstream sources</h2><p>Circuit breaker state and 24-hour fetch outcomes.</p></div>"
        f"<ul class='source-grid'>{''.join(cards)}</ul></section>"
    )


def _workers(data):
    items = []
    for name, worker in data["workers"].items():
        age, limit = worker["heartbeatAgeSeconds"], worker["stallAfterSeconds"]
        if worker["stopped"]:
            tone, state = "bad", "Stopped"
        elif worker["stalled"]:
            tone, state = "bad", "Stalled"
        elif age is None:
            tone, state = "idle", "Starting"
        else:
            tone, state = "ok", "Running"
        beat = "no heartbeat yet" if age is None else f"heartbeat {_span(age)} ago"
        items.append(
            f"<li class='{tone}'><span class='pulse' aria-hidden='true'></span>"
            f"<div><h3>{_e(WORKER_LABELS.get(name, name))}</h3><p>{_e(beat)} · stalls after {_span(limit)}</p>"
            f"{_meter(age or 0, limit, f'Heartbeat age {age or 0:.0f} of {limit:.0f} seconds', 0.5, 0.8)}</div>"
            f"{_chip(tone, state)}</li>"
        )
    body = (
        f"<ul class='worker-list'>{''.join(items)}</ul>"
        if items
        else "<p class='empty-state'>Background jobs are disabled on this instance.</p>"
    )
    return (
        "<section class='panel workers' aria-labelledby='workers-title'><div class='panel-head'>"
        "<h2 id='workers-title'>Background workers</h2><p>Heartbeat age against the stall threshold.</p></div>"
        f"{body}</section>"
    )


def _gauge(label, value_text, of_text, meter, note=""):
    of = f" <small>{_e(of_text)}</small>" if of_text else ""
    note = f"<p class='note'>{note}</p>" if note else ""
    return (
        f"<div class='gauge'><div class='gauge-head'><h3>{_e(label)}</h3><b>{_e(value_text)}{of}</b></div>"
        f"{meter}{note}</div>"
    )


def _resources(data):
    process, container, disk = data["process"], data["container"], data["storage"]
    gauges = []
    memory, limit = container["memoryBytes"], container["memoryLimitBytes"]
    if memory is not None and limit:
        share = _percent(memory, limit)
        gauges.append(
            _gauge(
                "Container memory",
                _size(memory),
                f"of {_size(limit)}",
                _meter(memory, limit, f"{share} % of the memory limit"),
                f"{share} % used · process RSS {_size(process['rssBytes'])}",
            )
        )
    else:
        used, host = memory or process["rssBytes"], container["hostMemoryBytes"]
        share = _percent(used, host)
        gauges.append(
            _gauge(
                "Container memory" if memory is not None else "Process memory",
                _size(used),
                f"of {_size(host)} host" if host else "",
                _meter(used, host, f"{share} % of host memory") if host else "",
                ("No cgroup memory limit · " if memory is not None else "")
                + f"process RSS {_size(process['rssBytes'])}",
            )
        )
    cores, cpu = container["cpuCores"] or 1, process["cpuPercent"]
    gauges.append(
        _gauge(
            "Process CPU",
            "–" if cpu is None else f"{cpu:g} %",
            f"of {cores:g} core{'s' if cores != 1 else ''}",
            _meter(cpu or 0, 100 * cores, "CPU use since the previous page load"),
            f"Since the previous page load · {process['cpuSeconds']:,} s CPU in total",
        )
    )
    volume = disk["dataDisk"]
    if volume:
        share = _percent(volume["usedBytes"], volume["totalBytes"])
        gauges.append(
            _gauge(
                "Data volume",
                _size(volume["usedBytes"]),
                f"of {_size(volume['totalBytes'])}",
                _meter(volume["usedBytes"], volume["totalBytes"], f"{share} % of the data volume used", 0.8, 0.9),
                f"{share} % used · {_size(volume['freeBytes'])} free",
            )
        )
    sizes = [
        ("Database", _size(disk["databaseBytes"]), "SQLite incl. WAL"),
        ("Log files", _size(disk["logBytes"]) if data["flags"]["logFiles"] else "off", "LOG_DIR"),
        ("Uptime", _span(data["uptimeSeconds"]), "since " + _time(data["startedAt"])),
    ]
    tiles = "".join(
        f"<div><dt>{_e(label)}</dt><dd>{_e(value)}</dd><dd class='hint'>{_e(hint)}</dd></div>"
        for label, value, hint in sizes
    )
    return (
        "<section class='panel resources' aria-labelledby='resources-title'><div class='panel-head'>"
        "<h2 id='resources-title'>Resources</h2><p>Bars turn amber and red as limits approach.</p></div>"
        f"<div class='gauges'>{''.join(gauges)}</div><dl class='tiles'>{tiles}</dl></section>"
    )


def _inventory(title, status, figures, now, extra=""):
    if status["error"]:
        chip = _chip("bad", "Error")
    elif status["checked"]:
        chip = _chip("ok", "Current")
    else:
        chip = _chip("idle", "Pending")
    numbers = "".join(f"<div><dd>{_n(value)}</dd><dt>{_e(label)}</dt></div>" for label, value in figures)
    error = f"<p class='error'>{_e(status['error'])}</p>" if status["error"] else ""
    return (
        f"<article class='inventory'><div class='source-head'><h3>{_e(title)}</h3>{chip}</div>"
        f"<dl class='big'>{numbers}</dl>"
        f"<p class='detail'>Updated {_when(status['checked'], now)} · last attempt {_when(status['attempted'], now)}"
        f"{extra}</p>{error}</article>"
    )


def _inventories(data, now):
    tmds = data["tmds"]
    if not tmds["enabled"]:
        body = (
            "<p class='empty-state'>Trend Micro Deep Security data is disabled (<code>TMDS_ENABLED=false</code>).</p>"
        )
    else:
        agents, ksp = tmds["agents"], tmds["ksp"]
        page = f" · page dated {_e(ksp['pageUpdated'])}" if ksp.get("pageUpdated") else ""
        body = (
            "<div class='inventory-grid'>"
            + _inventory("Bundled agents", agents, [("agent releases", agents["releases"])], now)
            + _inventory(
                "Kernel Support Packages",
                ksp,
                [("platforms", ksp["platforms"]), ("kernels", ksp["kernels"])],
                now,
                page,
            )
            + "</div>"
        )
    return (
        "<section class='panel inventories' aria-labelledby='inventories-title'><div class='panel-head'>"
        "<h2 id='inventories-title'>Trend Micro inventories</h2><p>Hourly feeds behind the TMDS columns.</p></div>"
        f"{body}</section>"
    )


def _limits(data):
    per_minute = data["limits"]["rateLimitsPerMinute"]
    windows = list(WINDOWS)
    rows = [
        [
            label,
            f"{per_minute[key]:,}/min" if per_minute[key] else "off",
            *(data["rateLimited"][w].get(budget, 0) for w in windows),
        ]
        for budget, label, key in BUDGETS
    ]
    known = {budget for budget, _, _ in BUDGETS}
    rows += [
        [budget, "–", *(data["rateLimited"][w].get(budget, 0) for w in windows)]
        for budget in sorted({b for counts in data["rateLimited"].values() for b in counts} - known)
    ]
    capacity = data["capacityRejected"]
    rows += [
        [label, "–", *(capacity[w][kind] for w in windows)]
        for kind, label in (("workspace", "Workspace watch limit (422)"), ("server", "Server watch capacity"))
    ]
    return (
        "<section class='panel limits' aria-labelledby='limits-title'><div class='panel-head'>"
        "<h2 id='limits-title'>Rejected requests</h2><p>Rejections per budget in the last hour, day and 14 days.</p></div>"
        "<div class='scroll'>"
        + _table(["Budget", "Limit", *(w.replace("h", " h").replace("d", " d") for w in windows)], rows)
        + "</div></section>"
    )


def _config(data):
    flags = data["flags"]
    labels = {
        "manualRefresh": "Manual refresh",
        "tmds": "Trend Micro data",
        "apiDocs": "OpenAPI schema",
        "hsts": "HSTS",
        "adminToken": "Admin token",
        "logFiles": "Log files",
    }
    items = [(label, flags[key]) for key, label in labels.items()]
    items += [(f"Legal page: {page}", on) for page, on in flags["legal"].items()]
    chips = "".join(
        f"<li class='{'on' if on else 'off'}'><span class='dot' aria-hidden='true'></span>{_e(label)}"
        f"<span class='sr-only'>: {'on' if on else 'off'}</span></li>"
        for label, on in items
    )
    return (
        "<section class='panel config' aria-labelledby='config-title'><div class='panel-head'>"
        "<h2 id='config-title'>Configuration</h2><p>Filled dots are enabled.</p></div>"
        f"<ul class='flags'>{chips}</ul></section>"
    )


def render(data):
    now = time.time()
    tone, state, reason = _health(data)
    generated = time.strftime("%H:%M:%S UTC", time.gmtime(now))
    header = (
        "<header class='top'><div class='brand'><span class='mark' aria-hidden='true'>?/</span>"
        "<h1>Is It Fixed <span class='tag'>admin</span></h1></div>"
        f"<div class='health {tone}' role='status'><span class='beacon' aria-hidden='true'></span>"
        f"<div><h2 class='sr-only'>System status</h2><strong>{_e(state)}</strong><span>{_e(reason)}</span></div></div>"
        f"<p class='meta'><span>Version <b>{_e(data['version'])}</b></span>"
        f"<span>Up <b>{_e(_span(data['uptimeSeconds']))}</b></span>"
        f"<span>Generated <b>{generated}</b> · refreshes every 30 s</span>"
        "<a href='/api/stats'>JSON</a></p></header>"
    )
    main = (
        _kpis(data)
        + _activity(data)
        + _sources(data, now)
        + _workers(data)
        + _resources(data)
        + _inventories(data, now)
        + _limits(data)
        + _config(data)
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'><meta http-equiv='refresh' content='30'>"
        f"<title>{_e(state)} · Is It Fixed admin</title><link rel='stylesheet' href='/admin.css'></head>"
        f"<body>{header}<main>{main}</main>"
        "<footer>Aggregate counters only: no IP addresses, workspace ids or links between CVEs and workspaces"
        " are recorded.</footer></body></html>"
    )


def authorized(header, token):
    scheme, _, credentials = (header or "").partition(" ")
    if scheme.lower() == "bearer":
        supplied = credentials.strip()
    elif scheme.lower() == "basic":
        try:
            supplied = base64.b64decode(credentials.strip(), validate=True).decode("utf-8").partition(":")[2]
        except (binascii.Error, UnicodeDecodeError):
            return False
    else:
        return False
    return hmac.compare_digest(supplied.encode(), token.encode())


def create_admin_app(public_app, settings):
    app = FastAPI(title="Is It Fixed admin", docs_url=None, redoc_url=None, openapi_url=None)
    sampler = ProcessSampler()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if settings.admin_token and not authorized(request.headers.get("authorization"), settings.admin_token):
            return JSONResponse(
                {"detail": "Authentication required."},
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Is It Fixed admin", charset="UTF-8"'},
            )
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(SecurityHeaders)

    def state():
        current = public_app.state
        if not hasattr(current, "workers"):  # set at the end of the public app startup
            raise HTTPException(503, "Starting up")
        return current

    @app.get("/api/stats")
    async def stats():
        return collect(state(), sampler)

    @app.get("/")
    async def dashboard():
        return HTMLResponse(render(collect(state(), sampler)))

    @app.get("/admin.css")
    async def stylesheet():
        return Response(STYLESHEET.read_bytes(), media_type="text/css", headers={"Cache-Control": "no-cache"})

    return app
