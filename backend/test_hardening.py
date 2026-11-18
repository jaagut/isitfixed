"""Tests for configuration, security headers, rate limits, limits/expiry, backoff, sanitized errors and logging."""

import asyncio
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
from backend.main import create_app
from backend.providers import Providers
from backend.ratelimit import RateLimiter
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
    assert settings.user_agent == f"CVE-Desk/{settings.version} (+https://example.com/src)"
    assert Settings.from_env({"ADMIN_PORT": "0"}).admin_port is None
    assert Settings.from_env({}).admin_port == 8081
    with pytest.raises(SettingsError, match="MANUAL_REFRESH"):
        Settings.from_env({"MANUAL_REFRESH": "maybe"})
    with pytest.raises(SettingsError, match="MAX_WATCHED_CVES"):
        Settings.from_env({"MAX_WATCHED_CVES": "lots"})


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
            "sourceUrl": "https://github.com/jaagut/cve-viewer",
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


def test_api_docs_are_off_by_default(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        for url in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(url).status_code == 404
    with TestClient(make_app(path, providers, clock, api_docs=True)) as client:
        assert client.get("/openapi.json").status_code == 200
        assert "cdn.jsdelivr.net" in client.get("/docs").headers["content-security-policy"]


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
        assert len(bodies) >= 3  # record, sles, rhel, final: each flushed separately
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


def test_rate_limiter_hashes_rotates_and_bounds_memory():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0], max_buckets=3)
    key = limiter.client_key("203.0.113.9")
    assert len(key) == 16 and b"203.0.113.9" not in key
    assert key == limiter.client_key("203.0.113.9") != limiter.client_key("203.0.113.10")
    assert [limiter.hit("api", key, 2) for _ in range(3)] == [0, 0, 30]
    now[0] += 30
    assert limiter.hit("api", key, 2) == 0
    for index in range(5):
        limiter.hit("api", bytes([index]), 1)
    assert len(limiter.buckets) == 3
    now[0] += 24 * 3600
    rotated = limiter.client_key("203.0.113.9")
    assert rotated != key and not limiter.buckets
    assert all("203.0.113" not in repr(bucket) for bucket in limiter.buckets)


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


def test_watch_limits(setup):
    clock, providers, path = setup
    cases = [{"id": f"CVE-2026-{1000 + i}", "families": []} for i in range(4)]
    with TestClient(make_app(path, providers, clock, max_watches_per_workspace=3, max_watched_cves=5)) as client:
        response = client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": cases})
        assert response.status_code == 422 and "at most 3" in response.json()["detail"]
        assert client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": cases[:2]}).status_code == 200
        more = [{"id": f"CVE-2026-{2000 + i}", "families": []} for i in range(2)]
        response = client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": [cases[0], *more]})
        assert response.status_code == 200
        response = client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": [*more, cases[2]]})
        assert response.status_code == 200  # cases[0] is still watched by WORKSPACE: 5 distinct CVEs.
        response = client.put(
            f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [*cases[:2], {"id": "CVE-2026-3000"}]}
        )
        assert response.status_code == 429


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
    assert cache.db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert [tuple(row) for row in cache.db.execute("SELECT id, last_seen FROM workspaces")] == [(WORKSPACE, 1234.0)]
    assert cache.watched(CVE)
    upgraded = cache.get(CVE)["payload"]
    assert upgraded["error"] == "CVE source unavailable: invalid data from source"
    assert upgraded["vendorData"]["sources"]["sles"]["error"] == "Vendor source unavailable: HTTP 503 from ftp.suse.com"
    assert cache.db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    cache.close()
    Cache(path).close()  # Re-opening an up-to-date database is a no-op.


# Health and watchdog


def test_health_reports_worker_heartbeats(setup):
    clock, providers, path = setup
    settings = Settings(**TEST_SETTINGS)
    with TestClient(create_app(path, providers=providers, clock=clock, settings=settings)) as client:
        body = client.get("/api/health").json()
        assert body["status"] == "ok" and set(body["workers"]) == {"refresh"}
        owner, task = client.app.state.workers["refresh"]
        owner.beat = time.monotonic() - 3600
        assert client.get("/api/health").json()["status"] == "degraded"
        assert client.get("/api/health").status_code == 200


def test_watchdog_exits_when_the_loop_is_stuck():
    now, exits = [0.0], []
    watchdog = Watchdog(timeout=120, exit=exits.append, clock=lambda: now[0])
    now[0] = 100
    assert watchdog.check() and not exits
    now[0] = 121
    assert not watchdog.check() and exits == [1]


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


def test_logging_rotates_into_log_dir_and_keeps_stdout_quiet(tmp_path, capsys):
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        old = tmp_path / "logs" / "cve-desk.log.2020-01-01"
        old.parent.mkdir()
        old.write_text("old")
        os.utime(old, (0, 0))
        logs.configure(Settings(log_dir=str(tmp_path / "logs"), log_retention_days=14))
        file_handler = next(h for h in root.handlers if isinstance(h, logging.handlers.TimedRotatingFileHandler))
        assert file_handler.backupCount == 13 and file_handler.utc and file_handler.when == "MIDNIGHT"
        logging.getLogger("cve-desk.test").info("client 192.0.2.7 looked up something")
        logging.getLogger("cve-desk.test").warning("visible warning")
        for handler in root.handlers:
            handler.flush()
        written = (tmp_path / "logs" / "cve-desk.log").read_text()
        assert "client [addr] looked up" in written and "192.0.2.7" not in written
        assert written.split()[0].endswith("Z")
        out = capsys.readouterr().out
        assert "visible warning" in out and "looked up" not in out
        assert not old.exists()
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        for handler in saved[0]:
            root.addHandler(handler)
        root.setLevel(saved[1])


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
