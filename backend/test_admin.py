import base64
import json

from fastapi.testclient import TestClient

from backend.admin import SOURCES, authorized, create_admin_app
from backend.test_backend import CVE, WORKSPACE, Clock, FakeProviders, make_app


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_token_accepts_bearer_or_basic_password():
    assert authorized("Bearer s3cret", "s3cret")
    assert authorized(basic("anyone", "s3cret"), "s3cret")
    for header in (None, "", "Bearer wrong", basic("s3cret", "wrong"), "Basic !!!", "Token s3cret"):
        assert not authorized(header, "s3cret")


def run(tmp_path, token=None):
    clock = Clock()
    providers = FakeProviders(clock)
    public = make_app(tmp_path / "admin.sqlite3", providers, clock, admin_token=token)
    return public, providers, create_admin_app(public, public.state.settings)


def test_admin_requires_the_token_when_configured(tmp_path):
    public, _, admin = run(tmp_path, token="s3cret")
    with TestClient(public), TestClient(admin) as client:
        for url in ("/", "/api/stats", "/admin.css"):
            response = client.get(url)
            assert response.status_code == 401 and response.headers["www-authenticate"].startswith("Basic")
        assert client.get("/api/stats", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert client.get("/", headers={"Authorization": basic("ops", "s3cret")}).status_code == 200


def test_admin_dashboard_and_stats_without_identifiers(tmp_path):
    public, providers, admin = run(tmp_path)
    with TestClient(public) as site, TestClient(admin) as client:
        site.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [{"id": CVE, "families": ["sles"]}]})
        site.get(f"/api/cves/{CVE}?families=sles")
        providers.fail = True
        site.get("/api/cves/CVE-2026-0001?families=sles")
        stats = client.get("/api/stats")
        assert stats.headers["cache-control"] == "no-store"
        data = stats.json()
        assert set(data) >= {
            "version",
            "uptimeSeconds",
            "flags",
            "data",
            "refreshes",
            "sources",
            "rateLimited",
            "tmds",
            "process",
            "container",
            "storage",
            "workers",
        }
        assert data["data"] == {"cachedCves": 1, "watchedCves": 1, "workspaces": 1}
        assert data["refreshes"]["1h"]["on_demand"] == 2 and data["refreshes"]["14d"]["scheduled"] == 0
        assert set(data["sources"]) == set(SOURCES)
        assert data["sources"]["sles"]["fetches"]["24h"] == 2 and data["sources"]["sles"]["failures"]["24h"] == 1
        assert data["sources"]["sles"]["lastError"] == "invalid data from source"
        assert data["process"]["rssBytes"] > 0
        assert data["storage"]["databaseBytes"] > 0 and data["storage"]["dataDisk"]["freeBytes"] > 0
        text = json.dumps(data)
        assert WORKSPACE not in text and CVE not in text and "testclient" not in text
        page = client.get("/")
        assert page.headers["content-type"].startswith("text/html")
        assert "<meta http-equiv='refresh' content='30'>" in page.text
        assert "<script" not in page.text and "style=" not in page.text
        assert "default-src 'self'" in page.headers["content-security-policy"]
        css = client.get("/admin.css")
        assert css.status_code == 200 and "prefers-color-scheme: dark" in css.text


def test_counters_persist_in_hourly_buckets(tmp_path):
    public, _, _ = run(tmp_path)
    with TestClient(public) as site:
        stats = site.app.state.stats
        stats.incr("refresh.manual", 2)
        stats.flush()
        stats.incr("refresh.manual")
        assert stats.totals(1)["refresh.manual"] == 3
        stats.clock.now += 15 * 24 * 3600
        stats.flush()
        assert stats.totals(24 * 14)["refresh.manual"] == 0


def test_admin_charts_include_pending_and_stored_buckets(tmp_path):
    public, _, admin = run(tmp_path)
    with TestClient(public), TestClient(admin) as client:
        stats = public.state.stats
        assert client.get("/").text.count("No data yet") == 4
        stats.incr("fetch.record", 2)
        stats.flush()
        stats.incr("fetch.rhel")
        stats.incr("refresh.manual")
        stats.clock.now += 3600
        stats.incr("failure.rhel")
        stats.incr("refresh.scheduled", 2)
        data = client.get("/api/stats").json()
        hourly = data["hourly"]
        assert len(hourly) == 24
        assert hourly[-2]["fetches"] == 3 and hourly[-1]["failures"] == 1
        assert hourly[-1]["hourUtc"] - hourly[0]["hourUtc"] == 23 * 3600
        assert hourly[-1]["refreshKinds"] == {"scheduled": 2, "on_demand": 0, "manual": 0}
        assert hourly[-1]["refreshes"] == 2 and hourly[-2]["refreshKinds"]["manual"] == 1
        daily = data["daily"]
        assert len(daily) == 14 and daily[-1]["dayUtc"] - daily[0]["dayUtc"] == 13 * 86400
        assert sum(day["fetches"] for day in daily) == 3 and sum(day["refreshes"] for day in daily) == 3
        assert stats.totals(1)["fetch.record"] == 0
        page = client.get("/").text
        assert "System status" in page and "Healthy" in page
        assert "<summary>Hourly counts</summary>" in page
        # Refreshes (24 h and 14 d) and fetches have data; the rate-limit chart stays empty.
        assert page.count("No data yet") == 1
        assert page.count("<svg viewBox='0 0 288 100' preserveAspectRatio='none' role='img'") == 4
        assert "Manual 1)" in page and "<title>" in page


def test_admin_shows_degraded_and_stalled_states(tmp_path):
    public, providers, admin = run(tmp_path)
    with TestClient(public) as site, TestClient(admin) as client:
        providers.fail = True
        site.get("/api/cves/CVE-2026-0001?families=sles")
        page = client.get("/").text
        assert "<strong>Degraded</strong>" in page and "CVE record, SUSE are failing" in page
        assert "invalid data from source" in page and ("class='source bad'" in page or "class='source warn'" in page)

        class Owner:
            beat = 0.0  # time.monotonic() at boot: long overdue

        class Task:
            def done(self):
                return False

        public.state.workers = {"maintenance": (Owner(), Task())}
        page = client.get("/").text
        assert "<strong>Stalled</strong>" in page and "Maintenance is not reporting" in page
        workers = client.get("/api/stats").json()["workers"]
        assert workers["maintenance"]["stalled"] and workers["maintenance"]["stallAfterSeconds"] > 0
