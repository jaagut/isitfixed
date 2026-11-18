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
