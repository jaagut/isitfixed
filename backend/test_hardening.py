"""Tests for configuration, security headers, rate limits, limits/expiry, backoff, sanitized errors and logging."""

import asyncio
import contextlib
import json
import logging
import logging.handlers
import os
import socket
import sqlite3
import ssl
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import legal as legal_module
from backend import logs
from backend.backoff import Breaker
from backend.cache import RETENTION, Cache
from backend.errors import NotPublished, Paused, TooLarge, describe, scrub
from backend.main import CASE_DEADLINE, STALL_AFTER, create_app
from backend.providers import Providers
from backend.ratelimit import RateLimiter, shorten
from backend.settings import ROOT, Settings, SettingsError
from backend.test_backend import CVE, OTHER, TEST_SETTINGS, WORKSPACE, Clock, FakeProviders, make_app
from backend.watchdog import Watchdog


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    return clock, FakeProviders(clock), tmp_path / "cache.sqlite3"


# Settings and /api/config


def test_settings_parse_environment():
    settings = Settings.from_env(
        {
            "MANUAL_REFRESH": "true",
            "TMDS_ENABLED": "0",
            "ADMIN_PORT": "",
            "LOG_RETENTION_DAYS": "30",
            "LEGAL_OPERATOR_ADDRESS": "Street 1\\n12345 Town",
            "CSP_CONNECT_SRC": "https://api.example.com, https://b.example.com",
            "SOURCE_URL": "https://example.com/src",
        }
    )
    assert settings.manual_refresh and not settings.tmds_enabled and settings.admin_port is None
    assert settings.log_retention_days == 14  # Capped.
    assert settings.legal_operator_address == "Street 1\n12345 Town"
    assert settings.csp_connect_src == ("https://api.example.com", "https://b.example.com")
    assert settings.user_agent == f"isitfixed/{settings.version} (+https://example.com/src)"
    assert Settings.from_env({"ADMIN_PORT": "0"}).admin_port is None
    assert Settings.from_env({}).admin_port == 8081
    with pytest.raises(SettingsError, match="MANUAL_REFRESH"):
        Settings.from_env({"MANUAL_REFRESH": "maybe"})
    with pytest.raises(SettingsError, match="MAX_WATCHED_CVES"):
        Settings.from_env({"MAX_WATCHED_CVES": "lots"})
    defaults = Settings.from_env({})
    assert (defaults.rate_limit_requests, defaults.rate_limit_lookups, defaults.rate_limit_watches) == (300, 30, 12)
    assert (defaults.max_cached_cves, defaults.max_watched_cves) == (1500, 1000)
    assert (defaults.max_workspaces, defaults.max_watch_rows) == (5000, 50000)
    limits = Settings.from_env({"MAX_WORKSPACES": "10", "MAX_WATCH_ROWS": "20"})
    assert (limits.max_workspaces, limits.max_watch_rows) == (10, 20)
    # Cached CVEs must exceed watched CVEs, so on-demand lookups always find room.
    with pytest.raises(SettingsError, match="MAX_CACHED_CVES"):
        Settings.from_env({"MAX_WATCHED_CVES": "1500"})
    with pytest.raises(SettingsError, match="MAX_CACHED_CVES"):
        Settings(max_cached_cves=100, max_watched_cves=100)
    # The watchdog timeout must cover at least three 5-second heartbeats (0 disables it).
    with pytest.raises(SettingsError, match="WATCHDOG_TIMEOUT"):
        Settings.from_env({"WATCHDOG_TIMEOUT": "10"})
    assert Settings.from_env({"WATCHDOG_TIMEOUT": "15"}).watchdog_timeout == 15
    assert Settings.from_env({"WATCHDOG_TIMEOUT": "0"}).watchdog_timeout == 0


def test_config_endpoint_and_manual_refresh_switch(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, manual_refresh=False)) as client:
        response = client.get("/api/config")
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "version": client.app.state.settings.version,
            "manualRefresh": False,
            "tmds": True,
            "legal": {"imprint": False, "privacy": False},
            "sourceUrl": "https://github.com/jaagut/isitfixed",
            "retentionDays": 10,
        }
        for url in (f"/api/cves/{CVE}?refresh=true", f"/api/cves/{CVE}/stream?refresh=true"):
            response = client.get(url)
            assert response.status_code == 403
            assert response.json() == {"detail": "Manual refresh is disabled on this server."}
        assert not providers.calls
        assert client.get(f"/api/cves/{CVE}?families=sles&refresh=false").status_code == 200


def test_version_comes_from_pyproject():
    import tomllib

    assert Settings().version == tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


# Security headers, compression, docs and static files


def test_security_headers_on_every_response(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, csp_connect_src=("https://api.example.com",))) as client:
        for url in ("/api/health", "/", "/missing", "/assets/logos/redhat.svg"):
            headers = client.get(url).headers
            csp = headers["content-security-policy"]
            assert "script-src 'self'" in csp and "style-src 'self'" in csp and "frame-ancestors 'none'" in csp
            assert "connect-src 'self' https://api.example.com" in csp
            assert "upgrade-insecure-requests" not in csp  # Plain HTTP request.
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["referrer-policy"] == "no-referrer"
            assert (
                "camera=()" in headers["permissions-policy"] and "browsing-topics=()" in headers["permissions-policy"]
            )
            assert headers["cross-origin-opener-policy"] == "same-origin"
            assert headers["cross-origin-resource-policy"] == "same-origin"
            assert headers["x-frame-options"] == "DENY"
            assert "strict-transport-security" not in headers
    with TestClient(make_app(path, providers, clock, hsts=True), base_url="https://testserver") as client:
        headers = client.get("/api/health").headers
        assert headers["strict-transport-security"].startswith("max-age=")
        assert "upgrade-insecure-requests" in headers["content-security-policy"]


def test_api_docs_are_off_by_default_and_only_the_schema_when_enabled(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        for url in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(url).status_code == 404
    with TestClient(make_app(path, providers, clock, api_docs=True)) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 200 and response.json()["info"]["title"] == "Is It Fixed"
        assert "jsdelivr" not in response.headers["content-security-policy"]
        # No Swagger UI or ReDoc: they would load third-party assets.
        assert client.get("/docs").status_code == 404 and client.get("/redoc").status_code == 404


def test_json_is_gzipped_but_the_stream_is_not(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        response = client.get(f"/api/cves/{CVE}?families=sles,rhel", headers={"Accept-Encoding": "gzip"})
        assert response.headers["content-encoding"] == "gzip"
        response = client.get(f"/api/cves/{CVE}/stream?families=sles,rhel", headers={"Accept-Encoding": "gzip"})
        assert "content-encoding" not in response.headers
        assert all(json.loads(line)["id"] == CVE for line in response.text.splitlines())


def test_stream_sends_one_body_message_per_line(setup):
    clock, providers, path = setup
    app = make_app(path, providers, clock)

    async def run():
        messages = []
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": f"/api/cves/{CVE}/stream",
            "raw_path": f"/api/cves/{CVE}/stream".encode(),
            "query_string": b"families=sles,rhel",
            "headers": [(b"host", b"testserver"), (b"accept-encoding", b"gzip")],
            "client": ("127.0.0.1", 5000),
            "server": ("testserver", 80),
        }
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.sleep(3600)

        async def send(message):
            messages.append(message)

        async with app.router.lifespan_context(app):
            await app(scope, receive, send)
        bodies = [m["body"] for m in messages if m["type"] == "http.response.body" and m.get("body")]
        assert len(bodies) >= 2  # progress snapshot(s) and the final result, each flushed separately
        assert all(body.endswith(b"\n") and body.count(b"\n") == 1 for body in bodies)
        start = next(m for m in messages if m["type"] == "http.response.start")
        assert b"content-encoding" not in dict(start["headers"])

    asyncio.run(run())


def test_tmds_payload_is_gzipped(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        client.app.state.inventory.cache.db.execute(
            "INSERT INTO agents VALUES (?,?,?,?)",
            ("a.zip", "rhel9", json.dumps({"kernels": ["k" * 40] * 200}), clock()),
        )
        response = client.get("/api/tmds", headers={"Accept-Encoding": "gzip"})
        assert response.headers["content-encoding"] == "gzip"
        assert response.headers["vary"] == "Accept-Encoding"


def test_static_cache_headers_for_sources_and_built_bundle(setup, tmp_path):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        assert client.get("/").headers["cache-control"] == "no-cache"
        assert client.get("/style.css").headers["cache-control"] == "no-cache"
        assert client.get("/src/app.js").headers["cache-control"] == "no-cache"
        assert client.get("/assets/logos/redhat.svg").headers["cache-control"] == "public, max-age=86400"
        assert client.get("/pyproject.toml").status_code == 404
    dist = tmp_path / "dist"
    (dist / "static").mkdir(parents=True)
    (dist / "assets").mkdir()
    (dist / "index.html").write_text("<!doctype html><script type=module src=/static/app-abc.js></script>")
    (dist / "static" / "app-abc.js").write_text("console.log(1)")
    (dist / "manifest.json").write_text(json.dumps({"/style.css": "/static/style-abc.css"}))
    with TestClient(make_app(path, providers, clock, frontend_dir=dist)) as client:
        assert client.get("/static/app-abc.js").headers["cache-control"] == "public, max-age=31536000, immutable"
        assert client.get("/CVE-2024-3094").text.startswith("<!doctype html>")
        assert client.get("/style.css").status_code == 404
        assert client.get("/src/app.js").status_code == 404
        assert client.app.state.legal.stylesheet == "/static/style-abc.css"


# Legal pages

FRAGMENT = (
    "<h2>Impressum</h2><address>{{operator_name}}<br>{{operator_address}}</address>"
    "<!-- if:operator_phone --><p>Tel: {{operator_phone}}</p><!-- endif:operator_phone -->"
    "<p>{{operator_email}} · {{log_retention_days}} · {{unknown}}</p>"
)


def test_legal_pages_render_from_legal_dir_with_escaping(setup, tmp_path, monkeypatch):
    clock, providers, path = setup
    monkeypatch.setattr(legal_module, "TEMPLATES", tmp_path / "no-templates")
    legal_dir = tmp_path / "legal"
    legal_dir.mkdir()
    (legal_dir / "imprint.html").write_text(FRAGMENT)
    settings = dict(
        legal_dir=str(legal_dir),
        legal_operator_name="Jane <Doe>",
        legal_operator_address="Street 1\n12345 Town",
        legal_operator_email="jane@example.com",
    )
    with TestClient(make_app(path, providers, clock, **settings)) as client:
        assert client.get("/api/config").json()["legal"] == {"imprint": True, "privacy": False}
        response = client.get("/imprint")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-cache"
        page = response.text
        assert "Jane &lt;Doe&gt;" in page and "Street 1<br>\n12345 Town" in page
        assert "Tel:" not in page and "{{" not in page and "· 14 ·" in page
        assert 'class="legal-page"' in page and 'class="legal-content"' in page and 'class="site-footer"' in page
        assert "<script" not in page and "style=" not in page
        assert 'href="/imprint"' in page and 'href="/privacy"' not in page
        assert client.get("/privacy").status_code == 404
        redirect = client.get("/impressum", follow_redirects=False)
        assert redirect.status_code == 301 and redirect.headers["location"] == "/imprint"
        assert client.get("/datenschutz", follow_redirects=False).headers["location"] == "/privacy"


def test_legal_pages_need_name_address_and_email(setup, tmp_path, monkeypatch, caplog):
    clock, providers, path = setup
    templates = tmp_path / "templates"
    templates.mkdir()
    for page in ("imprint", "privacy"):
        (templates / f"{page}.html").write_text(f"<h2>{page}</h2><p>{{{{operator_name}}}}</p>")
    monkeypatch.setattr(legal_module, "TEMPLATES", templates)
    with caplog.at_level(logging.WARNING), TestClient(make_app(path, providers, clock)) as client:
        assert client.get("/imprint").status_code == 404 and client.get("/privacy").status_code == 404
    assert "Legal pages not configured" in caplog.text
    complete = dict(legal_operator_name="Op", legal_operator_address="Addr", legal_operator_email="op@example.com")
    with TestClient(make_app(path, providers, clock, **complete)) as client:
        assert "<p>Op</p>" in client.get("/privacy").text
        assert client.get("/api/config").json()["legal"] == {"imprint": True, "privacy": True}


def test_template_blocks_and_placeholders():
    rendered = legal_module.render(
        "<!-- if:a -->A{{a}}<!-- if:b -->B<!-- endif:b --><!-- endif:a --><!-- if:c -->C<!-- endif:c -->{{body}}",
        {"a": "<x>", "b": ""},
        raw={"body": "<p>{{a}}</p>"},
    )
    assert rendered == "A&lt;x&gt;<p>{{a}}</p>"


# Rate limiting


def test_rate_limiter_keys_on_shortened_addresses_and_bounds_memory():
    assert shorten("203.0.113.9") == "203.0.113.0/24"
    assert shorten("2001:db8:1234:5678::1") == "2001:db8:1234::/48"
    assert shorten("::ffff:198.51.100.7") == "198.51.100.0/24"
    assert shorten("fe80::1%eth0") == "fe80::/48"
    assert shorten("testclient") == shorten(None) == "unknown"
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0], max_buckets=3)
    key = limiter.client_key("203.0.113.9")
    assert key == limiter.client_key("203.0.113.200") != limiter.client_key("203.0.114.9")
    assert [limiter.hit("api", key, 2) for _ in range(3)] == [0, 0, 30]
    now[0] += 30
    assert limiter.hit("api", key, 2) == 0
    for index in range(5):
        limiter.hit("api", f"192.0.{index}.0/24", 1)
    assert len(limiter.buckets) == 3  # least recently used buckets are dropped first
    # Buckets expire with their window; nothing about the full address is kept.
    now[0] += 60
    limiter.hit("api", key, 2)
    assert list(limiter.buckets) == [("api", "203.0.113.0/24")]
    assert "203.0.113.9" not in repr(limiter.buckets)


def test_clients_in_one_prefix_share_a_budget_and_rejections_are_counted(setup):
    clock, providers, path = setup
    app = make_app(path, providers, clock, rate_limit_requests=2)
    with TestClient(app, client=("198.51.100.7", 1234)) as first:
        assert [first.get("/api/config").status_code for _ in range(2)] == [200, 200]
        # Further clients share the running app (no second lifespan).
        assert TestClient(app, client=("198.51.100.99", 1234)).get("/api/config").status_code == 429  # same /24
        assert TestClient(app, client=("198.51.101.7", 1234)).get("/api/config").status_code == 200
        stats = first.app.state.stats
        stats.flush()
        assert stats.totals(1)["ratelimited.requests"] == 1
        stored = [tuple(row) for row in first.app.state.cache.db.execute("SELECT * FROM stats")]
        assert "198.51.100" not in repr(stored)


def test_api_request_budget_returns_429_with_retry_after(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, rate_limit_requests=3)) as client:
        assert [client.get("/api/config").status_code for _ in range(4)] == [200, 200, 200, 429]
        response = client.get("/api/config")
        assert response.status_code == 429 and int(response.headers["retry-after"]) >= 1
        assert "Too many requests" in response.json()["detail"]
        assert client.get("/api/health").status_code == 200  # Health checks are never limited.
        assert client.get("/").status_code == 200  # Static files are not limited.
        assert client.app.state.stats.totals(1)["ratelimited.requests"] == 2


def test_only_uncached_lookups_use_the_lookup_budget(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, rate_limit_lookups=2)) as client:
        assert client.get(f"/api/cves/{CVE}?families=sles").status_code == 200
        for _ in range(5):  # Cached and fresh: no upstream fetch, no budget used.
            assert client.get(f"/api/cves/{CVE}?families=sles").status_code == 200
        assert client.get("/api/cves/CVE-2026-0002?families=").status_code == 200
        response = client.get("/api/cves/CVE-2026-0003/stream?families=")
        assert response.status_code == 429 and response.headers["retry-after"]
        assert client.app.state.stats.totals(1)["ratelimited.lookups"] == 1
    with TestClient(make_app(path, providers, clock, rate_limit_lookups=10, rate_limit_lookups_global=1)) as client:
        assert client.get("/api/cves/CVE-2026-0004?families=").status_code == 200
        assert client.get("/api/cves/CVE-2026-0005?families=").status_code == 429
        assert client.app.state.stats.totals(1)["ratelimited.lookups-global"] == 1


def test_watch_sync_budget(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, rate_limit_watches=2)) as client:
        url = f"/api/workspaces/{WORKSPACE}/watches"
        codes = [client.put(url, json={"cases": []}).status_code for _ in range(3)]
        assert codes == [200, 200, 429]


# Watch limits, workspace expiry and schema migration


def cases_from(start, count):
    return [{"id": f"CVE-2026-{start + i}", "families": []} for i in range(count)]


def test_watch_limits(setup):
    clock, providers, path = setup
    cases = cases_from(1000, 4)
    with TestClient(make_app(path, providers, clock, max_watches_per_workspace=3, max_watched_cves=5)) as client:
        response = client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": cases})
        assert response.status_code == 422 and "at most 3" in response.json()["detail"]
        assert client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": cases[:2]}).status_code == 200
        more = cases_from(2000, 2)
        response = client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": [cases[0], *more]})
        assert response.status_code == 200
        response = client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": [*more, cases[2]]})
        assert response.status_code == 200  # cases[0] is still watched by WORKSPACE: 5 distinct CVEs.
        response = client.put(
            f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [*cases[:2], {"id": "CVE-2026-3000"}]}
        )
        assert response.status_code == 429 and response.headers["retry-after"] == "3600"
        # Replacing a CVE with one that another workspace already watches keeps the distinct count.
        response = client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [cases[0], more[0]]})
        assert response.status_code == 200
        stats = client.app.state.stats
        assert stats.totals(1)["capacity.workspace"] == 1 and stats.totals(1)["capacity.server"] == 1


def test_watch_caps_count_rows_and_workspaces_and_always_allow_reductions(setup):
    clock, providers, path = setup
    third = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    url = "/api/workspaces/{}/watches"
    with TestClient(make_app(path, providers, clock, max_workspaces=2, max_watch_rows=4)) as client:
        assert client.put(url.format(WORKSPACE), json={"cases": cases_from(1000, 2)}).status_code == 200
        assert client.put(url.format(OTHER), json={"cases": cases_from(1000, 2)}).status_code == 200
        # A third workspace exceeds MAX_WORKSPACES; an empty list creates none and is fine.
        assert client.put(url.format(third), json={"cases": cases_from(1000, 1)}).status_code == 429
        assert client.put(url.format(third), json={"cases": []}).status_code == 200
        # Rows: 4 of 4 used; growing a workspace fails, swapping entries does not.
        assert client.put(url.format(OTHER), json={"cases": cases_from(1000, 3)}).status_code == 429
        assert client.put(url.format(OTHER), json={"cases": cases_from(1005, 2)}).status_code == 200
        assert client.app.state.cache.counts() == {"cachedCves": 0, "watchedCves": 4, "workspaces": 2}
    # Caps lowered below the current counts: reductions still pass, growth does not.
    lowered = dict(
        max_workspaces=1, max_watch_rows=2, max_watched_cves=1, max_cached_cves=2, max_watches_per_workspace=1
    )
    with TestClient(make_app(path, providers, clock, **lowered)) as client:
        assert client.put(url.format(OTHER), json={"cases": cases_from(1005, 2)}).status_code == 200  # unchanged
        assert client.put(url.format(OTHER), json={"cases": cases_from(1005, 1)}).status_code == 200
        assert client.put(url.format(OTHER), json={"cases": cases_from(1005, 2)}).status_code == 422
        assert client.put(url.format(WORKSPACE), json={"cases": []}).status_code == 200
        assert client.app.state.cache.counts() == {"cachedCves": 0, "watchedCves": 1, "workspaces": 1}


def test_capacity_check_and_replacement_are_one_transaction(setup):
    clock, providers, path = setup
    cache = Cache(path)
    try:
        limits = dict(per_workspace=10, watched_cves=2, watch_rows=10, workspaces=10)
        cache.replace_watches(WORKSPACE, cases_from(1000, 2), clock(), limits)
        with pytest.raises(Exception, match="capacity"):
            cache.replace_watches(OTHER, cases_from(2000, 1), clock(), limits)
        assert not cache.db.in_transaction
        assert [row[0] for row in cache.db.execute("SELECT DISTINCT workspace FROM watches")] == [WORKSPACE]
    finally:
        cache.close()


def test_inactive_workspaces_expire_and_start_the_retention_clock(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, workspace_ttl_days=30)) as client:
        cache = client.app.state.service.cache
        for workspace in (WORKSPACE, OTHER):
            client.put(f"/api/workspaces/{workspace}/watches", json={"cases": [{"id": CVE, "families": []}]})
        client.get(f"/api/cves/{CVE}?families=")
        clock.now += 20 * 86400
        client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": [{"id": CVE, "families": []}]})  # Renewed.
        clock.now += 11 * 86400
        client.portal.call(client.app.state.service.tick)
        assert cache.counts()["workspaces"] == 1 and cache.watched(CVE)
        clock.now += 20 * 86400
        client.portal.call(client.app.state.service.tick)
        assert cache.counts() == {"cachedCves": 1, "watchedCves": 0, "workspaces": 0}
        assert cache.get(CVE)["unwatched_since"] == clock()
        clock.now += RETENTION
        client.portal.call(client.app.state.service.tick)
        assert cache.get(CVE) is None


def test_workspace_expiry_runs_in_bounded_batches(setup):
    clock, providers, path = setup
    cache = Cache(path)
    try:
        for index in range(7):
            workspace = f"{index:08d}-0000-0000-0000-000000000000"
            cache.sync_watches(workspace, [{"id": CVE, "families": []}], clock())
        cache.put(CVE, dict(payload={}, families=set(), unwatched_since=None, attempted=clock()))
        clock.now += 31 * 86400
        cutoff = clock() - 30 * 86400
        assert cache.prune_workspaces(cutoff, clock(), batch=3) == 3
        assert cache.counts()["workspaces"] == 4 and cache.get(CVE)["unwatched_since"] is None
        assert cache.prune_workspaces(cutoff, clock(), batch=3) == 3
        assert cache.prune_workspaces(cutoff, clock(), batch=3) == 1
        assert cache.prune_workspaces(cutoff, clock(), batch=3) == 0
        assert cache.counts()["watchedCves"] == 0 and cache.get(CVE)["unwatched_since"] == clock()
    finally:
        cache.close()


def test_existing_databases_upgrade_in_place(tmp_path):
    path = tmp_path / "old.sqlite3"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE cases (id TEXT PRIMARY KEY, payload TEXT NOT NULL, families TEXT NOT NULL,"
        " unwatched_since REAL, attempted REAL NOT NULL)"
    )
    db.execute(
        "CREATE TABLE watches (workspace TEXT NOT NULL, id TEXT NOT NULL, families TEXT NOT NULL, PRIMARY KEY (workspace, id))"
    )
    db.execute("CREATE TABLE agents (filename TEXT PRIMARY KEY, product TEXT, payload TEXT, seen REAL)")
    db.execute("INSERT INTO watches VALUES (?, ?, ?)", (WORKSPACE, CVE, "[]"))
    payload = {
        "error": "CVE source unavailable: Expecting value: line 1 column 1 (char 0)",
        "vendorData": {"sources": {"sles": {"error": "Vendor source unavailable: HTTP 503 from ftp.suse.com"}}},
    }
    db.execute("INSERT INTO cases VALUES (?, ?, ?, NULL, 1)", (CVE, json.dumps(payload), "[]"))
    db.commit()
    db.close()
    cache = Cache(path, clock=lambda: 1234.0)
    assert cache.db.execute("PRAGMA user_version").fetchone()[0] == 3
    assert [tuple(row) for row in cache.db.execute("SELECT id, last_seen FROM workspaces")] == [(WORKSPACE, 1234.0)]
    assert cache.watched(CVE)
    upgraded = cache.get(CVE)["payload"]
    assert upgraded["error"] == "CVE source unavailable: invalid data from source"
    assert upgraded["vendorData"]["sources"]["sles"]["error"] == "Vendor source unavailable: HTTP 503 from ftp.suse.com"
    assert cache.db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    cache.close()
    Cache(path).close()  # Re-opening an up-to-date database is a no-op.


# Health and watchdog


def test_health_is_degraded_for_failing_sources_and_503_when_a_worker_stalls(setup):
    clock, providers, path = setup
    settings = Settings(**TEST_SETTINGS)
    with TestClient(create_app(path, providers=providers, clock=clock, settings=settings)) as client:
        body = client.get("/api/health").json()
        assert body["status"] == "ok" and set(body["workers"]) == {"refresh", "maintenance"}
        assert body["stalled"] == [] and body["failingSources"] == []
        client.app.state.breaker.record("ubuntu", ValueError("offline"))
        response = client.get("/api/health")
        assert response.status_code == 200 and response.json()["status"] == "degraded"
        assert response.json()["failingSources"] == ["ubuntu"]
        # Within its bound (longest step plus pause and margin) a busy worker is fine.
        owner, task = client.app.state.workers["refresh"]
        owner.beat = time.monotonic() - (STALL_AFTER["refresh"] - 30)
        assert client.get("/api/health").status_code == 200
        owner.beat = time.monotonic() - (STALL_AFTER["refresh"] + 1)
        response = client.get("/api/health")
        assert response.status_code == 503 and response.json()["status"] == "stalled"
        assert response.json()["stalled"] == ["refresh"]
        owner.beat = time.monotonic()
        maintenance_owner, maintenance = client.app.state.workers["maintenance"]
        maintenance.cancel()  # A dead loop is stalled too.
        with contextlib.suppress(BaseException):
            client.portal.call(asyncio.sleep, 0)
        assert client.get("/api/health").json()["stalled"] == ["maintenance"]
    assert STALL_AFTER["refresh"] >= CASE_DEADLINE + 60
    assert STALL_AFTER["tmds-agents"] > 600  # an agent archive may take up to 10 minutes


def test_watchdog_exits_when_the_loop_is_stuck():
    now, exits, reports = [0.0], [], []
    watchdog = Watchdog(timeout=120, exit=exits.append, clock=lambda: now[0], report=reports.append)
    now[0] = 100
    assert watchdog.check() and not exits
    now[0] = 121
    assert not watchdog.check() and exits == [1] and reports == [121]


def test_watchdog_reports_on_stderr_without_logging(capfd, monkeypatch):
    import backend.watchdog as watchdog_module

    def no_logging(*args, **kwargs):
        raise AssertionError("the watchdog must not use logging")

    monkeypatch.setattr(logging.Logger, "_log", no_logging)
    exits = []
    watchdog = watchdog_module.Watchdog(timeout=15, exit=exits.append, clock=lambda: 100.0)
    watchdog.beat = 0.0
    assert not watchdog.check() and exits == [1]
    assert "event loop unresponsive for 100 seconds" in capfd.readouterr().err


# Sanitized errors and backoff


def test_errors_map_to_short_categories():
    request = httpx.Request("GET", "https://ubuntu.com/security/cves/CVE-2026-1.json")

    def wrapped(cause, message="boom"):
        error = httpx.ConnectError(message, request=request)
        error.__cause__ = cause
        return error

    assert describe(wrapped(socket.gaierror(-3, "Temporary failure in name resolution"))) == "DNS lookup failed"
    assert describe(httpx.ConnectError("[Errno -3] Temporary failure in name resolution", request=request)) == (
        "DNS lookup failed"
    )
    assert describe(wrapped(ssl.SSLCertVerificationError("certificate verify failed"))) == "TLS error"
    assert describe(httpx.ConnectError("[Errno 111] Connection refused", request=request)) == (
        "connection failed (ubuntu.com)"
    )
    assert describe(httpx.ReadTimeout("slow", request=request)) == "request timed out"
    assert describe(TimeoutError()) == "request timed out"
    assert describe(TooLarge()) == "response too large"
    assert describe(ValueError("Expected CSAF 2.0 at /internal/path")) == "invalid data from source"
    assert describe(RuntimeError("secret detail")) == "unexpected error"
    assert describe(Paused(0)) == "temporarily paused after repeated failures; next attempt after 00:00 UTC"
    assert scrub("connect to 10.1.2.3 and 2001:db8::1 failed") == "connect to [addr] and [addr] failed"


def test_repeated_failures_pause_a_source_and_success_resets_it(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        providers.fail = True
        for index in range(3):
            clock.now += 61
            client.get(f"/api/cves/CVE-2026-{5000 + index}?families=sles")
        calls = len(providers.calls)
        clock.now += 1
        response = client.get("/api/cves/CVE-2026-6000?families=sles")
        assert len(providers.calls) == calls  # Neither record nor SLES was contacted.
        assert response.status_code == 502
        assert response.json()["detail"].startswith(
            "CVE source unavailable: temporarily paused after repeated failures; next attempt after "
        )
        breaker = client.app.state.breaker
        assert breaker.snapshot()["sles"]["consecutiveFailures"] == 3
        providers.fail = False
        clock.now += 61  # 1 minute pause after the third failure.
        body = client.get(f"/api/cves/{CVE}?families=sles").json()
        assert "error" not in body["vendorData"]["sources"]["sles"]
        assert breaker.snapshot()["sles"]["consecutiveFailures"] == 0


def test_paused_source_keeps_evidence_and_reports_retry_after(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        client.get(f"/api/cves/{CVE}?families=sles")
        providers.fail = True
        for _ in range(3):
            clock.now += 61
            body = client.get(f"/api/cves/{CVE}?families=sles&refresh=true").json()
        source = body["vendorData"]["sources"]["sles"]
        assert body["vendorData"]["evidence"]["sles15"]
        assert source["retryAfter"] == int((clock() + 60) * 1000)
        assert "paused" not in source["error"]  # The failure that opened the breaker is reported as such.
        clock.now += 61
        source = client.get(f"/api/cves/{CVE}?families=sles&refresh=true").json()["vendorData"]["sources"]["sles"]
        assert "temporarily paused" not in source["error"]  # Pause expired: a real attempt was made.


def test_breaker_backoff_doubles_and_ignores_not_published():
    now = [0.0]
    breaker = Breaker(clock=lambda: now[0], threshold=1)
    breaker.record("ubuntu", NotPublished("missing"))
    assert breaker.retry_after("ubuntu") is None
    delays = []
    for _ in range(7):
        breaker.record("ubuntu", ValueError())
        delays.append(breaker.retry_after("ubuntu") - now[0])
    assert delays == [60, 120, 240, 480, 960, 1800, 1800]
    with pytest.raises(Paused):
        breaker.check("ubuntu")
    breaker.success("ubuntu")
    breaker.check("ubuntu")


def test_slow_drip_download_hits_the_overall_deadline(monkeypatch):
    import backend.providers as providers_module

    monkeypatch.setattr(providers_module, "DOCUMENT_DEADLINE", 0.3)

    async def drip():
        while True:
            await asyncio.sleep(0.05)
            yield b" "

    async def handler(request):
        return httpx.Response(200, content=drip())

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = Providers(client)
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                await provider.get_json("https://ubuntu.com/security/cves/CVE-2026-1.json")
            assert time.monotonic() - started < 2
            assert not provider.pending

    asyncio.run(run())


def test_oversized_documents_are_rejected():
    async def handler(request):
        return httpx.Response(200, headers={"content-length": str(1 << 30)}, content=b"{}")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(TooLarge):
                await Providers(client).get_json("https://ubuntu.com/x.json")

    asyncio.run(run())


# Logging


@pytest.fixture
def root_logger():
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    yield root
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    for handler in saved[0]:
        root.addHandler(handler)
    root.setLevel(saved[1])
    logs._handler = None


def test_logging_writes_into_log_dir_and_keeps_stdout_quiet(tmp_path, capsys, root_logger):
    old = tmp_path / "logs" / "isitfixed.log.2020-01-01"
    old.parent.mkdir()
    old.write_text("old")
    logs.configure(Settings(log_dir=str(tmp_path / "logs"), log_retention_days=14))
    assert isinstance(logs._handler, logs.DailyFileHandler)
    logging.getLogger("isitfixed.test").info("client 192.0.2.7 looked up something")
    logging.getLogger("isitfixed.test").warning("visible warning")
    for handler in root_logger.handlers:
        handler.flush()
    written = (tmp_path / "logs" / "isitfixed.log").read_text()
    assert "client [addr] looked up" in written and "192.0.2.7" not in written
    assert written.split()[0].endswith("Z")
    out = capsys.readouterr().out
    assert "visible warning" in out and "looked up" not in out
    assert not old.exists()  # older than the retention period: deleted at startup


def test_log_files_rotate_at_midnight_utc_without_new_lines_and_expire_by_age(tmp_path, root_logger):
    day = 86400
    now = [1_700_000_000.0 - 1_700_000_000.0 % day + 23 * 3600]  # 23:00 UTC
    directory = tmp_path / "logs"
    logs.configure(Settings(log_dir=str(directory), log_retention_days=3), clock=lambda: now[0])
    logging.getLogger("isitfixed.test").info("first day")
    first = time.strftime("%Y-%m-%d", time.gmtime(now[0]))
    now[0] += 3600 + 30  # 00:00:30 UTC: nothing is logged, the maintenance loop rotates
    logs.maintain()
    assert sorted(path.name for path in directory.iterdir()) == [f"isitfixed.log.{first}"]
    assert "first day" in (directory / f"isitfixed.log.{first}").read_text()
    logging.getLogger("isitfixed.test").info("second day")
    assert "second day" in (directory / "isitfixed.log").read_text()
    days = [time.strftime("%Y-%m-%d", time.gmtime(now[0] + offset * day)) for offset in range(4)]
    for offset in range(1, 4):
        now[0] += day
        logs.maintain()
        logging.getLogger("isitfixed.test").info("day %d", offset)
    # Retention of 3 days: the active file plus the two previous days; older files are deleted.
    names = sorted(path.name for path in directory.iterdir())
    assert names == ["isitfixed.log", f"isitfixed.log.{days[1]}", f"isitfixed.log.{days[2]}"]
    assert "day 3" in (directory / "isitfixed.log").read_text()


def test_a_log_file_left_from_an_earlier_day_is_rotated_at_startup(tmp_path, root_logger):
    directory = tmp_path / "logs"
    directory.mkdir()
    stale = directory / "isitfixed.log"
    stale.write_text("yesterday")
    yesterday = time.time() - 86400
    os.utime(stale, (yesterday, yesterday))
    logs.configure(Settings(log_dir=str(directory), log_retention_days=14))
    rotated = directory / f"isitfixed.log.{time.strftime('%Y-%m-%d', time.gmtime(yesterday))}"
    assert rotated.read_text() == "yesterday" and not stale.exists()


def test_bundled_privacy_policy_mentions_access_logs_only_when_enabled(setup):
    clock, providers, path = setup
    operator = dict(legal_operator_name="Op", legal_operator_address="Addr", legal_operator_email="op@example.com")
    with TestClient(make_app(path, providers, clock, **operator)) as client:
        page = client.get("/privacy").text
        assert "Zugriffsprotokolle" not in page and "access logs" not in page
        assert "<h1>" in page and "{{" not in page and "if:" not in page
    with TestClient(make_app(path, providers, clock, legal_access_logs=True, **operator)) as client:
        page = client.get("/privacy").text
        assert "Zugriffsprotokolle" in page and "access logs" in page


def test_retention_removes_pre_rebrand_logs(tmp_path):
    from .logs import remove_old_logs

    legacy = tmp_path / "cve-desk.log.2020-01-01"
    legacy.write_text("old log")
    remove_old_logs(tmp_path, 14)
    assert not legacy.exists()


def test_oversized_indexer_stdout_does_not_deadlock_cleanup(tmp_path, monkeypatch):
    from backend import providers as module

    script = tmp_path / "large_index.py"
    script.write_text("import os\nwhile True: os.write(1, b'x' * 65536)\n")
    monkeypatch.setattr(module, "INDEXER", script)
    monkeypatch.setattr(module, "INDEX_LIMIT", 1024)

    async def no_download(*args, **kwargs):
        pass

    monkeypatch.setattr(module, "download_to", no_download)

    async def run():
        async with httpx.AsyncClient() as client:
            with pytest.raises(TooLarge):
                await asyncio.wait_for(Providers(client)._debian_index("https://example.org/feed"), timeout=3)

    asyncio.run(run())


def test_cancelled_inventory_attempt_is_retryable_after_restart(tmp_path):
    from backend.jobs import HourlyJob

    class Interrupted(HourlyJob):
        async def run(self):
            started.set()
            await asyncio.Event().wait()

    async def run():
        nonlocal started
        started = asyncio.Event()
        cache = Cache(tmp_path / "jobs.sqlite3")
        try:
            job = Interrupted(cache, None)
            task = asyncio.create_task(job.tick())
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            restarted = Interrupted(cache, None)
            assert restarted.checked is None
            assert restarted.due()
        finally:
            cache.close()

    started = None
    asyncio.run(run())


def test_legal_favicon_uses_packaged_frontend_asset(tmp_path, monkeypatch):
    import hashlib

    # Container images carry assets only in FRONTEND_DIR, not the source checkout.
    monkeypatch.setattr(legal_module, "ROOT", tmp_path / "missing-source")
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    icon = dist / "assets/icon.svg"
    icon.write_text("<svg/>")
    pages = legal_module.LegalPages(Settings(frontend_dir=dist))
    assert pages.values["favicon"] == "/assets/icon.svg?v=" + hashlib.sha256(icon.read_bytes()).hexdigest()[:12]
    icon.write_text("<svg>changed</svg>")
    assert legal_module.LegalPages(Settings(frontend_dir=dist)).values["favicon"] != pages.values["favicon"]
