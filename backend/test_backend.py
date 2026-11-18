import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.cache import RETENTION, Cache
from backend.main import Service, create_app
from backend.providers import (
    DEADLINES,
    PRODUCTS,
    NotPublished,
    Providers,
    alpine,
    alpine_evidence,
    csaf,
    debian,
    describe,
    ubuntu,
)
from backend.settings import Settings

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
        self.unknown, self.unpublished, self.slow = set(), set(), set()

    def prune(self, clear=False):
        pass

    async def record(self, cve):
        self.calls.append(("record", cve))
        await asyncio.sleep(0)
        if self.fail:
            raise ValueError("offline")
        if cve in self.unknown:
            raise NotPublished("CVE ID not found in the CVE Program.")
        return {"cveMetadata": {"cveId": cve}, "containers": {"cna": {"title": "A case"}}}

    async def vendor(self, family, cve):
        self.calls.append((family, cve))
        if self.fail:
            raise ValueError("vendor offline")
        if family in self.slow:
            await asyncio.sleep(5)
        if family in self.unpublished or cve in self.unknown:
            if family in ("debian", "alpine"):
                return {}, dict(url="https://vendor.example/bulk.json", checked=self.clock() * 1000, mode="API cache")
            raise NotPublished(f"{family} has not published a document for this CVE yet.")
        if family == "sles":
            data, metadata = csaf(FIXTURE, cve, "sles")
        else:
            data, metadata = {"rhel9": []}, {}
        return data, dict(
            url="https://vendor.example/source.json", checked=self.clock() * 1000, mode="API cache", **metadata
        )


TEST_SETTINGS = dict(
    manual_refresh=True,
    rate_limit_requests=0,
    rate_limit_lookups=0,
    rate_limit_lookups_global=0,
    rate_limit_watches=0,
    admin_port=None,
)


def make_app(path, providers, clock, **overrides):
    settings = Settings(**{**TEST_SETTINGS, **overrides})
    return create_app(path, providers=providers, clock=clock, background=False, settings=settings)


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    providers = FakeProviders(clock)
    return clock, providers, tmp_path / "cache.sqlite3"


def test_api_cache_force_cooldown_and_validation(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
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
    with TestClient(make_app(path, providers, clock)) as client:
        watches = f"/api/workspaces/{WORKSPACE}/watches"
        assert client.put(watches, json={"cases": [{"id": CVE, "families": ["sles"]}]}).status_code == 200
        body = client.get(f"/api/cves/{CVE}?families=sles").json()
        assert body["cache"]["watched"] and body["cache"]["expiresAt"] is None
        clock.now += 29 * 86400  # Within the 30-day workspace inactivity limit.
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
    with TestClient(make_app(path, providers, clock)) as client:
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
    with TestClient(make_app(path, providers, clock)) as client:
        url = f"/api/workspaces/{WORKSPACE}/watches"
        for cases in ([{"id": CVE, "families": ["unknown"]}], [{"id": CVE, "notes": "private"}], [{"id": "bad"}]):
            assert client.put(url, json={"cases": cases}).status_code == 422
        assert not providers.calls


def test_source_failure_preserves_previous_evidence_and_timestamps(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        url = f"/api/cves/{CVE}?families=sles&refresh=true"
        initial = client.get(url).json()
        providers.fail, clock.now = True, clock.now + 61
        failed = client.get(url).json()
        assert failed["vendorData"]["evidence"] == initial["vendorData"]["evidence"]
        assert failed["vendorData"]["sources"]["sles"]["checked"] == initial["vendorData"]["sources"]["sles"]["checked"]
        assert failed["checked"] == initial["checked"]
        # Raw exception text never reaches the API; the category does.
        assert failed["error"] == "CVE source unavailable: invalid data from source"
        assert failed["vendorData"]["sources"]["sles"]["error"] == "Vendor source unavailable: invalid data from source"
        assert "offline" not in json.dumps(failed)


def test_empty_failed_lookup_is_not_a_safe_result(setup):
    clock, providers, path = setup
    providers.fail = True
    with TestClient(make_app(path, providers, clock)) as client:
        assert client.get(f"/api/cves/{CVE}?families=sles").status_code == 502


def test_cache_and_watches_survive_restart_and_startup_prunes_expired_data(setup):
    clock, providers, path = setup

    def app():
        return make_app(path, providers, clock)

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
    data = ubuntu(
        {
            "id": CVE,
            "packages": [
                {
                    "name": "linux",
                    "statuses": [{"release_codename": "noble", "status": "pending", "description": "6.8.0"}],
                }
            ],
        },
        CVE,
    )
    assert data["ubuntu2404"][0]["status"] == "affected"
    assert data["ubuntu2404"][0]["fix"] == []
    data = debian({"linux": {CVE: {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0"}}}}}, CVE)
    assert data["debian12"][0]["status"] == "unaffected"
    assert alpine({"packages": []}, CVE) == []


ALPINE_DOC = {
    "packages": [
        {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": [f"{CVE} GHSA-xxxx", "CVE-2026-1"], "3.3.1-r0": []}}},
        {"pkg": {"name": "curl", "secfixes": {"8.9.0-r0": [CVE]}}},
    ]
}
DEBIAN_DOC = {
    "linux": {
        CVE: {
            "releases": {"bookworm": {"status": "open"}, "trixie": {"status": "resolved", "fixed_version": "6.12.1"}}
        },
        "CVE-2026-1": {"releases": {"bullseye": {"status": "open"}}},
    },
    "zlib": {CVE: {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0", "nodsa": "Minor issue"}}}},
}


def test_http_provider_shares_bulk_feeds_and_keeps_only_compact_indexes():
    clock, calls = Clock(), []

    async def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=ALPINE_DOC)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = Providers(client, clock)
            url = "https://secdb.alpinelinux.org/v3.22/main.json"
            indexes = await asyncio.gather(*(provider.get_feed(url, "alpine") for _ in range(4)))
            assert len(calls) == 1
            assert indexes[0] == {
                CVE: [("openssl", "3.3.2-r0"), ("curl", "8.9.0-r0")],
                "GHSA-xxxx": [("openssl", "3.3.2-r0")],
                "CVE-2026-1": [("openssl", "3.3.2-r0")],
            }
            assert alpine_evidence(indexes[0][CVE]) == alpine(ALPINE_DOC, CVE)
            assert provider.memory.used == 0
            clock.now += 3600
            provider.prune()
            assert not provider.feeds

    asyncio.run(run())


def test_debian_feed_is_indexed_in_a_child_process(tmp_path):
    async def handler(request):
        return httpx.Response(200, json=DEBIAN_DOC)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = Providers(client, Clock(), spool_dir=tmp_path)
            result, metadata = await provider.vendor("debian", CVE)
            assert metadata["url"].startswith("https://security-tracker.debian.org/")
            assert result == debian(DEBIAN_DOC, CVE)
            assert [(e["name"], e["status"]) for e in result["debian12"]] == [
                ("linux", "affected"),
                ("zlib", "unaffected"),
            ]
            assert result["debian13"][0]["fix"] == ["linux 6.12.1"]
            assert result["debian12"][1]["note"] == ""  # no-dsa only qualifies open issues
            index = provider.feeds["https://security-tracker.debian.org/tracker/data/json"][0]
            assert set(index) == {CVE} and isinstance(index[CVE], bytes)  # compact JSON per CVE, other releases dropped
            assert not list(tmp_path.iterdir())  # the spooled download is removed

    asyncio.run(run())


def test_invalid_debian_feed_is_a_source_error(tmp_path):
    async def handler(request):
        return httpx.Response(200, text="[1, 2")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = Providers(client, Clock(), spool_dir=tmp_path)
            with pytest.raises(ValueError):
                await provider.vendor("debian", CVE)
            assert describe(ValueError()) == "invalid data from source" and not provider.feeds

    asyncio.run(run())


def test_unknown_cve_is_404_and_not_cached(setup):
    clock, providers, path = setup
    providers.unknown.add("CVE-2026-9999991")
    with TestClient(make_app(path, providers, clock)) as client:
        response = client.get("/api/cves/CVE-2026-9999991?families=debian,sles")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]
        assert client.app.state.service.cache.ids() == []


def test_full_cache_evicts_oldest_unwatched_entry(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock, max_cached_cves=2, max_watched_cves=1)) as client:
        cache = client.app.state.service.cache
        client.put(f"/api/workspaces/{WORKSPACE}/watches", json={"cases": [{"id": "CVE-2026-0001", "families": []}]})
        for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
            clock.now += 1
            assert client.get(f"/api/cves/{cve}?families=").status_code == 200
        assert sorted(cache.ids()) == ["CVE-2026-0001", "CVE-2026-0003"]
        # Even at the watched-CVE limit, the reserved cache slot keeps on-demand lookups available.
        assert client.get("/api/cves/CVE-2026-0004?families=").status_code == 200
        assert sorted(cache.ids()) == ["CVE-2026-0001", "CVE-2026-0004"]


def test_unpublished_vendor_document_is_not_an_outage(setup):
    clock, providers, path = setup
    providers.unpublished.add("sles")
    with TestClient(make_app(path, providers, clock)) as client:
        body = client.get(f"/api/cves/{CVE}?families=sles").json()
        source = body["vendorData"]["sources"]["sles"]
        assert "not published" in source["notPublished"] and "error" not in source and source["checked"]
        assert "error" not in body


def test_new_vendor_selection_fetches_only_that_vendor(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        client.get(f"/api/cves/{CVE}?families=sles")
        attempted = client.app.state.service.cache.get(CVE)["attempted"]
        providers.calls.clear()
        clock.now += 120
        client.get(f"/api/cves/{CVE}?families=sles,rhel")
        assert providers.calls == [("rhel", CVE)]
        assert client.app.state.service.cache.get(CVE)["attempted"] == attempted


def test_slow_vendor_times_out_without_blocking_others(setup, monkeypatch):
    clock, providers, path = setup
    providers.slow.add("rhel")
    monkeypatch.setitem(DEADLINES, "rhel", 0.05)
    with TestClient(make_app(path, providers, clock)) as client:
        body = client.get(f"/api/cves/{CVE}?families=sles,rhel").json()
        assert body["vendorData"]["sources"]["rhel"]["error"] == "Vendor source unavailable: request timed out"
        assert body["vendorData"]["evidence"]["sles15"]


def test_source_errors_are_short():
    request = httpx.Request("GET", "https://ubuntu.com/security/cves/CVE-2026-1.json")
    error = httpx.HTTPStatusError("boom", request=request, response=httpx.Response(503, request=request))
    assert describe(error) == "HTTP 503 from ubuntu.com"


def test_suse_cloud_images_are_excluded_from_os_rows():
    doc = {
        "document": {"csaf_version": "2.0", "references": []},
        "product_tree": {
            "relationships": [
                {
                    "product_reference": "openssh",
                    "relates_to_product_reference": "SUSE Linux Enterprise Server 15 SP6",
                    "full_product_name": {
                        "product_id": "sp6:openssh",
                        "name": "openssh as component of SUSE Linux Enterprise Server 15 SP6",
                    },
                },
                {
                    "product_reference": "openssh",
                    "relates_to_product_reference": "SLES 15 SP5 CHOST Images for Google",
                    "full_product_name": {
                        "product_id": "img:openssh",
                        "name": "openssh as component of SLES 15 SP5 CHOST Images for Google",
                    },
                },
            ]
        },
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {"fixed": ["sp6:openssh"], "known_affected": ["img:openssh"]},
                "remediations": [],
            }
        ],
    }
    data, metadata = csaf(doc, CVE, "sles")
    assert [e["status"] for e in data["sles15"]] == ["fixed"]
    assert metadata["excludedImages"] == 1


def test_debian_11_is_no_longer_offered():
    assert "debian11" not in PRODUCTS


def test_progressive_sources_publish_before_slow_vendor(tmp_path):
    async def check():
        clock = Clock()
        gate = asyncio.Event()

        class Delayed(FakeProviders):
            async def vendor(self, family, cve):
                if family == "ubuntu":
                    await gate.wait()
                return await super().vendor(family, cve)

        cache = Cache(tmp_path / "progress.sqlite")
        service = Service(cache, Delayed(clock), clock)
        snapshots = []
        ready = asyncio.Event()

        def publish(payload):
            snapshots.append(payload)
            if payload.get("record"):
                ready.set()

        task = asyncio.create_task(service.get(CVE, {"rhel", "ubuntu"}, publish=publish))
        await asyncio.wait_for(ready.wait(), 1)
        assert not task.done()
        assert "ubuntu" not in snapshots[-1]["vendorData"]["sources"]
        gate.set()
        result = await task
        assert "ubuntu" in result["vendorData"]["sources"]
        assert "ubuntu" not in snapshots[0]["vendorData"]["sources"]
        cache.close()

    asyncio.run(check())


def test_case_links_serve_the_app_and_other_paths_stay_private(setup):
    clock, providers, path = setup
    with TestClient(make_app(path, providers, clock)) as client:
        for url in ("/CVE-2024-3094", "/cve-2024-3094"):
            response = client.get(url)
            assert response.status_code == 200 and "<script" in response.text
        for url in ("/cache.sqlite3", "/backend", "/CVE-2024-3094.json"):
            assert client.get(url).status_code == 404


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("queue", ["case_lock", "refresh_capacity"])
def test_deadline_marks_stale_sources_while_refresh_is_queued(setup, force, queue):
    clock, providers, path = setup

    async def run():
        cache = Cache(path, clock)
        service = Service(cache, providers, clock)
        try:
            original = await service.get(CVE, {"sles"})
            clock.now += 61 if force else 3601
            blocker = service.locks[CVE] if queue == "case_lock" else asyncio.Semaphore(0)
            if queue == "case_lock":
                await blocker.acquire()
            else:
                service.capacity = blocker
            try:
                result = await service.get(CVE, {"sles"}, force=force, deadline=0.01)
            finally:
                blocker.release()
            assert result["record"] == original["record"]
            assert result["vendorData"]["evidence"] == original["vendorData"]["evidence"]
            assert result["error"] == "CVE source unavailable: request timed out"
            assert result["vendorData"]["sources"]["sles"]["error"] == "Vendor source unavailable: request timed out"
            assert len(providers.calls) == 2  # The queued refresh never contacted upstream.
        finally:
            cache.close()

    asyncio.run(run())


def test_deadline_keeps_completed_source_errors_while_another_source_is_pending(setup):
    clock, providers, path = setup

    async def run():
        cache = Cache(path, clock)
        service = Service(cache, providers, clock)
        try:
            await service.get(CVE, {"sles", "debian"})
            clock.now += 3601
            vendor = providers.vendor

            async def refresh_vendor(family, cve):
                if family == "sles":
                    raise ValueError("bad upstream data")
                await asyncio.Event().wait()
                return await vendor(family, cve)

            providers.vendor = refresh_vendor
            completed_errors = []

            def publish(payload):
                error = payload["vendorData"]["sources"].get("sles", {}).get("error")
                if error:
                    completed_errors.append(error)

            result = await service.get(CVE, {"sles", "debian"}, deadline=0.05, publish=publish)
            assert completed_errors
            assert result["vendorData"]["sources"]["sles"]["error"] == completed_errors[-1]
            assert "timed out" not in completed_errors[-1]
            assert result["vendorData"]["sources"]["debian"]["error"] == "Vendor source unavailable: request timed out"
            assert "error" not in result  # The CVE record refresh completed successfully.
        finally:
            cache.close()

    asyncio.run(run())
