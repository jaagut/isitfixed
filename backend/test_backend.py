import asyncio
import json
from pathlib import Path

from fastapi.testclient import TestClient
import httpx
import pytest

from backend.cache import Cache, RETENTION
from backend.main import Service, create_app
from backend.providers import Providers, csaf, ubuntu, debian, alpine

CVE = "CVE-2026-98432"
WORKSPACE = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
OTHER = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
FIXTURE = json.loads((Path(__file__).parents[1] / "tests/fixtures/suse-cve-2026-98432.json").read_text())


class Clock:
    def __init__(self):
        self.now = 1700000000

    def __call__(self):
        return self.now


class FakeProviders:
    def __init__(self, clock):
        self.clock, self.calls, self.fail = clock, [], False

    def prune(self, clear=False):
        pass

    async def record(self, cve):
        self.calls.append(("record", cve))
        await asyncio.sleep(0)
        if self.fail:
            raise ValueError("offline")
        return {"cveMetadata": {"cveId": cve}, "containers": {"cna": {"title": "A case"}}}

    async def vendor(self, family, cve):
        self.calls.append((family, cve))
        if self.fail:
            raise ValueError("vendor offline")
        if family == "sles":
            data, metadata = csaf(FIXTURE, cve, "sles")
        else:
            data, metadata = {"rhel9": []}, {}
        return data, dict(url="https://vendor.example/source.json", checked=self.clock() * 1000, mode="API cache", **metadata)


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    providers = FakeProviders(clock)
    return clock, providers, tmp_path / "cache.sqlite3"


def test_api_cache_force_cooldown_and_validation(setup):
    clock, providers, path = setup
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        assert client.get("/api/health").status_code == 200
        for url in ("/api/cves/invalid", f"/api/cves/{CVE}?families=http://evil", f"/api/cves/{CVE}?refresh=invalid"):
            assert client.get(url).status_code == 422
        assert not providers.calls
        url = f"/api/cves/{CVE}?families=sles"
        first = client.get(url)
        assert first.status_code == 200
        assert first.headers["cache-control"] == "no-store"
        assert first.json()["vendorData"]["evidence"]["sles15"]
        assert client.get(url + "&refresh=true").json()["cache"]["lastAttempt"] == clock() * 1000
        assert len(providers.calls) == 2
        clock.now += 61
        assert client.get(url + "&refresh=true").status_code == 200
        assert len(providers.calls) == 4
        assert client.get("/data/cache.sqlite3").status_code == 404
        assert client.get("/backend/main.py").status_code == 404


def test_watched_cases_survive_closed_browsers_then_expire_after_unwatch(setup):
    clock, providers, path = setup
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        watches = f"/api/workspaces/{WORKSPACE}/watches"
        assert client.put(watches, json={"cases": [{"id": CVE, "families": ["sles"]}]}).status_code == 200
        body = client.get(f"/api/cves/{CVE}?families=sles").json()
        assert body["cache"]["watched"] and body["cache"]["expiresAt"] is None
        clock.now += 30 * 86400
        client.portal.call(client.app.state.service.tick)
        assert client.app.state.service.cache.get(CVE) is not None
        assert len(providers.calls) == 4  # Background refreshed while no browser requested it.
        assert client.put(watches, json={"cases": []}).status_code == 200
        removed = clock()
        clock.now += RETENTION - 1
        # Reading retained data does not renew the unwatched deadline.
        assert client.get(f"/api/cves/{CVE}?families=sles").json()["cache"]["expiresAt"] == (removed + RETENTION) * 1000
        count = len(providers.calls)
        client.portal.call(client.app.state.service.tick)
        assert len(providers.calls) == count  # Unwatched cases are not refreshed by the worker.
        clock.now += 1
        client.portal.call(client.app.state.service.tick)
        assert client.app.state.service.cache.get(CVE) is None


def test_last_workspace_removal_starts_timer_and_rewatch_cancels_it(setup):
    clock, providers, path = setup
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        for workspace in (WORKSPACE, OTHER):
            client.put(f"/api/workspaces/{workspace}/watches", json={"cases": [{"id": CVE, "families": []}]})
        client.get(f"/api/cves/{CVE}?families=")
        client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": []})
        assert client.app.state.service.cache.get(CVE)["unwatched_since"] is None
        client.put(f"/api/workspaces/{OTHER}/watches", json={"cases": []})
        assert client.app.state.service.cache.get(CVE)["unwatched_since"] == clock()
        clock.now += RETENTION - 1
        client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [{"id": CVE, "families": []}]})
        assert client.app.state.service.cache.get(CVE)["unwatched_since"] is None


def test_watch_validation_rejects_notes_and_unknown_sources(setup):
    clock, providers, path = setup
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        url = f"/api/workspaces/{WORKSPACE}/watches"
        for cases in ([{"id": CVE, "families": ["unknown"]}], [{"id": CVE, "notes": "private"}], [{"id": "bad"}]):
            assert client.put(url, json={"cases": cases}).status_code == 422
        assert not providers.calls


def test_source_failure_preserves_previous_evidence_and_timestamps(setup):
    clock, providers, path = setup
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        url = f"/api/cves/{CVE}?families=sles&refresh=true"
        initial = client.get(url).json()
        providers.fail, clock.now = True, clock.now + 61
        failed = client.get(url).json()
        assert failed["vendorData"]["evidence"] == initial["vendorData"]["evidence"]
        assert failed["vendorData"]["sources"]["sles"]["checked"] == initial["vendorData"]["sources"]["sles"]["checked"]
        assert failed["checked"] == initial["checked"]
        assert "offline" in failed["error"]
        assert "offline" in failed["vendorData"]["sources"]["sles"]["error"]


def test_empty_failed_lookup_is_not_a_safe_result(setup):
    clock, providers, path = setup
    providers.fail = True
    with TestClient(create_app(path, providers=providers, clock=clock, background=False)) as client:
        assert client.get(f"/api/cves/{CVE}?families=sles").status_code == 502


def test_cache_and_watches_survive_restart_and_startup_prunes_expired_data(setup):
    clock, providers, path = setup
    def app():
        return create_app(path, providers=providers, clock=clock, background=False)
    with TestClient(app()) as client:
        client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [{"id": CVE, "families": []}]})
        client.get(f"/api/cves/{CVE}?families=")
    with TestClient(app()) as client:
        assert client.app.state.service.cache.watched(CVE)
        assert client.app.state.service.cache.get(CVE)
        client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": []})
    clock.now += RETENTION
    with TestClient(app()) as client:
        assert client.app.state.service.cache.get(CVE) is None


def test_concurrent_lookups_share_one_upstream_refresh(setup):
    clock, providers, path = setup
    async def run():
        cache = Cache(path)
        try:
            service = Service(cache, providers, clock)
            await asyncio.gather(*(service.get(CVE, {"sles"}) for _ in range(8)))
            assert len(providers.calls) == 2
        finally:
            cache.close()
    asyncio.run(run())


def test_unwatch_during_refresh_is_not_overwritten(setup):
    clock, providers, path = setup
    cache = Cache(path)
    try:
        cache.sync_watches(WORKSPACE, [{"id": CVE, "families": []}], clock())
        cache.put(CVE, dict(payload={}, families=set(), unwatched_since=None, attempted=clock()))
        stale = cache.get(CVE)
        cache.sync_watches(WORKSPACE, [], clock())
        cache.put(CVE, stale)
        assert cache.get(CVE)["unwatched_since"] == clock()
    finally:
        cache.close()


def test_csaf_recommended_scope_major_versions_and_missing_cve():
    data, metadata = csaf(FIXTURE, CVE, "sles")
    assert len(data["sles15"]) == 2
    assert any(e["status"] == "fixed" and "15 SP4-LTSS" in e["name"] for e in data["sles15"])
    assert all("16.0" in e["name"] for e in data["sles16"])
    assert metadata["advisories"]
    modified = json.loads(json.dumps(FIXTURE))
    modified["vulnerabilities"][0]["remediations"] = []
    assert csaf(modified, CVE, "sles")[0]["sles16"][0]["status"] == "unknown"
    with pytest.raises(ValueError):
        csaf(FIXTURE, "CVE-2026-1111", "sles")


def test_distribution_semantics_are_preserved():
    data = ubuntu({"id": CVE, "packages": [{"name": "linux", "statuses": [{"release_codename": "noble", "status": "pending", "description": "6.8.0"}]}]}, CVE)
    assert data["ubuntu2404"][0]["status"] == "affected"
    assert data["ubuntu2404"][0]["fix"] == []
    data = debian({"linux": {CVE: {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0"}}}}}, CVE)
    assert data["debian12"][0]["status"] == "unaffected"
    assert alpine({"packages": []}, CVE) == []


def test_http_provider_shares_bulk_feeds_and_expires_memory_cache():
    clock, calls = Clock(), []
    async def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"packages": []})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = Providers(client, clock)
            await asyncio.gather(*(provider.get_json("https://secdb.alpinelinux.org/v3.22/main.json", shared=True) for _ in range(4)))
            assert len(calls) == 1
            clock.now += 3600
            provider.prune()
            assert not provider.raw
    asyncio.run(run())
