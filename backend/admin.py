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

from .security import SecurityHeaders
from .stats import WINDOWS

SOURCES = ("record", "rhel", "sles", "ubuntu", "debian", "alpine", "tmds-agents", "tmds-ksp")
REFRESH_KINDS = ("scheduled", "on_demand", "manual")
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
        self.wall, self.cpu = time.monotonic(), 0.0

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


def container_memory():
    return {
        "memoryBytes": _number(_read("/sys/fs/cgroup/memory.current")),
        "memoryLimitBytes": _number(_read("/sys/fs/cgroup/memory.max")),  # "max" (unlimited) → null
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
        "workers": {name: {"heartbeatAgeSeconds": age, "stopped": done} for name, (age, done) in workers.items()},
    }


def _size(value):
    if value is None:
        return "–"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _time(ms):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ms / 1000)) if ms else "–"


def _duration(seconds):
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days}d {hours}h {rest // 60}m"


def _table(headers, rows):
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render(data):
    windows = list(WINDOWS)
    flags = data["flags"]
    process, container, disk = data["process"], data["container"], data["storage"]
    sections = [
        (
            "Overview",
            _table(
                ["Version", "Uptime", "Cached CVEs", "Watched CVEs", "Workspaces"],
                [
                    [
                        data["version"],
                        _duration(data["uptimeSeconds"]),
                        data["data"]["cachedCves"],
                        data["data"]["watchedCves"],
                        data["data"]["workspaces"],
                    ]
                ],
            ),
        ),
        (
            "Settings",
            _table(
                ["Flag", "Value"],
                [[name, value] for name, value in flags.items() if name != "legal"]
                + [[f"legal.{page}", on] for page, on in flags["legal"].items()]
                + [["rateLimit." + name, value] for name, value in data["limits"]["rateLimitsPerMinute"].items()],
            ),
        ),
        (
            "Refreshes",
            _table(
                ["Kind", *windows],
                [[kind, *(data["refreshes"][w][kind] for w in windows)] for kind in REFRESH_KINDS],
            ),
        ),
        (
            "Upstream sources",
            _table(
                [
                    "Source",
                    *(f"fetches {w}" for w in windows),
                    *(f"failures {w}" for w in windows),
                    "Last error",
                    "Paused until",
                ],
                [
                    [
                        name,
                        *(source["fetches"][w] for w in windows),
                        *(source["failures"][w] for w in windows),
                        f"{source['lastError']} ({_time(source['lastErrorAt'])})" if source["lastError"] else "–",
                        _time(source["pausedUntil"]),
                    ]
                    for name, source in data["sources"].items()
                ],
            ),
        ),
        (
            "Rate limiting (429 responses)",
            _table(
                ["Budget", *windows],
                [
                    [budget, *(data["rateLimited"][w].get(budget, 0) for w in windows)]
                    for budget in sorted({b for counts in data["rateLimited"].values() for b in counts})
                ]
                or [["none", *(0 for _ in windows)]],
            ),
        ),
        (
            "Trend Micro inventories",
            _table(
                ["Inventory", "Last success", "Last attempt", "Error", "Contents"],
                [
                    [
                        "Bundled agents",
                        _time(data["tmds"]["agents"]["checked"]),
                        _time(data["tmds"]["agents"]["attempted"]),
                        data["tmds"]["agents"]["error"] or "–",
                        f"{data['tmds']['agents']['releases']} releases",
                    ],
                    [
                        "Kernel Support Packages",
                        _time(data["tmds"]["ksp"]["checked"]),
                        _time(data["tmds"]["ksp"]["attempted"]),
                        data["tmds"]["ksp"]["error"] or "–",
                        f"{data['tmds']['ksp']['platforms']} platforms, {data['tmds']['ksp']['kernels']} kernels",
                    ],
                ]
                if data["tmds"]["enabled"]
                else [["disabled (TMDS_ENABLED=false)", "–", "–", "–", "–"]],
            ),
        ),
        (
            "Resources",
            _table(
                ["Metric", "Value"],
                [
                    ["Process RSS", _size(process["rssBytes"])],
                    ["Process CPU", "–" if process["cpuPercent"] is None else f"{process['cpuPercent']} %"],
                    ["Container memory", _size(container["memoryBytes"])],
                    ["Container memory limit", _size(container["memoryLimitBytes"])],
                    ["Database", _size(disk["databaseBytes"])],
                    ["Data volume free", _size((disk["dataDisk"] or {}).get("freeBytes"))],
                    ["Data volume total", _size((disk["dataDisk"] or {}).get("totalBytes"))],
                    ["Log files", _size(disk["logBytes"])],
                ],
            ),
        ),
        (
            "Workers",
            _table(
                ["Worker", "Last heartbeat (s ago)", "State"],
                [
                    [
                        name,
                        "–" if w["heartbeatAgeSeconds"] is None else w["heartbeatAgeSeconds"],
                        "stopped" if w["stopped"] else "running",
                    ]
                    for name, w in data["workers"].items()
                ]
                or [["none", "–", "background jobs disabled"]],
            ),
        ),
    ]
    body = "".join(f"<section><h2>{html.escape(title)}</h2>{content}</section>" for title, content in sections)
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'><meta http-equiv='refresh' content='30'>"
        "<title>Is It Fixed admin</title><link rel='stylesheet' href='/admin.css'></head>"
        f"<body><header><h1>Is It Fixed admin</h1><p>Generated {generated} · refreshes every 30 s · "
        "<a href='/api/stats'>JSON</a></p></header>"
        f"<main>{body}</main></body></html>"
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
