import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.backoff import Breaker
from backend.cache import RETENTION, Cache
from backend.ksp import PAGE, KernelSupport, parse
from backend.main import create_app
from backend.settings import Settings

FIXTURE = (Path(__file__).parent / "fixtures" / "ksp-kernels.html").read_text()


class Clock:
    def __init__(self):
        self.now = 1790000000.0

    def __call__(self):
        return self.now


def test_parse_reads_packages_kernels_marks_and_notes():
    page = parse(FIXTURE)
    assert page.updated == "November 18, 2026, 12:16 UTC"
    assert page.notes == ["To use KSP 20.0.1 or later, DSM 20.0.883+ and DSA 20.0.0-8453+ are required."]
    # Only supported products are kept (no amazon2, no suse12).
    assert sorted(page.platforms) == [
        ("debian13", "x86_64"),
        ("rhel8", "x86_64"),
        ("rhel9", "aarch64"),
        ("rhel9", "x86_64"),
        ("sles15", "x86_64"),
        ("ubuntu2404", "x86_64"),
    ]
    rhel9 = page.platforms[("rhel9", "x86_64")]
    assert rhel9.package["filename"] == "KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip"
    assert rhel9.package["release"] == "20.0.3-36500"
    assert rhel9.package["download"] == (
        "https://files.trendmicro.com/products/deepsecurity/en/20.0/KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip"
    )
    assert rhel9.package["sha256"] == rhel9.package["sha256"].lower() and len(rhel9.package["sha256"]) == 64
    assert rhel9.kernels == [
        ("5.14.0-70.13.1.el9_0.x86_64", "default", False),
        ("5.14.0-611.5.1.el9_7.x86_64", "default", True),  # Δ cell
        ("5.14.0-611.5.1.el9_7.x86_64+cloud", "cloud", False),
    ]
    # A footnote mark after the filename is ignored.
    aarch64 = page.platforms[("rhel9", "aarch64")]
    assert aarch64.package["filename"] == "KernelSupport-RedHat_EL9-20.0.3-36000.aarch64.zip"
    assert aarch64.kernels == [("5.14.0-70.13.1.el9_0.aarch64", "default", False)]
    assert page.platforms[("sles15", "x86_64")].kernels == [
        ("5.14.21-150500.33.69-azure", "azure", False),
        ("6.4.0-150700.53.31-default", "default", False),
    ]
    assert ("6.12.38+deb13-cloud-amd64", "cloud", False) in page.platforms[("debian13", "x86_64")].kernels
    ubuntu = page.platforms[("ubuntu2404", "x86_64")]
    assert ubuntu.kernels == [("6.8.0-31-generic", "generic", False), ("6.8.0-1068-azure", "azure", False)]
    assert ubuntu.package["download"] is None  # Links outside the official download path are dropped.
    assert page.platforms[("rhel8", "x86_64")].package is None  # Kernel table without a package row.


def test_parse_tolerates_whitespace_and_attribute_changes():
    changed = FIXTURE.replace("<td>", "<td class='x'>\n  ").replace("<h3>", '<h3 id="h">  ').replace("</td>", " </td>")
    page = parse(changed)
    assert page.platforms[("rhel9", "x86_64")].kernels[1] == ("5.14.0-611.5.1.el9_7.x86_64", "default", True)


def test_parse_rejects_unrecognised_pages():
    with pytest.raises(ValueError):
        parse("<html><body><h1>Maintenance</h1></body></html>")


def make(tmp_path, clock, client=None):
    cache = Cache(tmp_path / "ksp.sqlite3", clock)
    return cache, KernelSupport(cache, client, clock, Breaker(clock, thresholds={"tmds-ksp": 1}))


def kernels(ksp, product, arch="x86_64"):
    entry = next(e for e in ksp.products()[product] if e["architecture"] == arch)
    return {(k[0], k[1]): k for k in entry["kernels"]}


def test_since_is_null_on_first_observation_then_the_current_release(tmp_path):
    clock = Clock()
    cache, ksp = make(tmp_path, clock)
    ksp.store(parse(FIXTURE), clock())
    first = kernels(ksp, "rhel9")
    assert first[("5.14.0-70.13.1.el9_0.x86_64", "default")] == ["5.14.0-70.13.1.el9_0.x86_64", "default", None, False]
    assert first[("5.14.0-611.5.1.el9_7.x86_64", "default")][3] is True

    clock.now += 3600
    newer = FIXTURE.replace("20.0.3-36500", "20.0.3-36600").replace(
        "<td>5.14.0-70.13.1.el9_0.x86_64</td>",
        "<td>5.14.0-70.13.1.el9_0.x86_64</td><td></td><td>Y</td></tr><tr><td>5.14.0-700.1.1.el9_8.x86_64</td>",
    )
    ksp.store(parse(newer), clock())
    second = kernels(ksp, "rhel9")
    assert second[("5.14.0-700.1.1.el9_8.x86_64", "default")][2] == "20.0.3-36600"
    assert second[("5.14.0-70.13.1.el9_0.x86_64", "default")][2] is None  # Unchanged for known kernels.
    entry = next(e for e in ksp.products()["rhel9"] if e["architecture"] == "x86_64")
    assert entry["release"] == "20.0.3-36600" and entry["platform"] == "rhel9"
    # A platform observed for the first time later still starts with null.
    assert all(k[2] is None for k in kernels(ksp, "rhel9", "aarch64").values())
    cache.close()


def test_kernels_not_seen_for_ten_days_are_dropped(tmp_path):
    clock = Clock()
    cache, ksp = make(tmp_path, clock)
    ksp.store(parse(FIXTURE), clock())
    clock.now += RETENTION - 60
    reduced = FIXTURE.replace("<tr><td>6.8.0-1068-azure</td>", "<tr><td>x</td>")
    ksp.store(parse(reduced), clock())
    ksp.cleanup()
    assert ("6.8.0-1068-azure", "azure") in kernels(ksp, "ubuntu2404")
    clock.now += 120
    ksp.cleanup()
    assert ("6.8.0-1068-azure", "azure") not in kernels(ksp, "ubuntu2404")
    assert ("6.8.0-31-generic", "generic") in kernels(ksp, "ubuntu2404")
    cache.close()


def test_failed_fetch_keeps_last_good_data_with_a_sanitized_error(tmp_path):
    clock = Clock()
    state = {"fail": False}

    async def handler(request):
        if state["fail"]:
            raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution", request=request)
        return httpx.Response(200, text=FIXTURE)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cache, ksp = make(tmp_path, clock, client)
            await ksp.tick()
            assert ksp.error is None and ksp.checked == clock()
            checked = ksp.checked
            clock.now += 3600
            state["fail"] = True
            await ksp.tick()
            snapshot = ksp.snapshot()
            assert snapshot["error"] == "DNS lookup failed"
            assert "Errno" not in str(snapshot)
            assert snapshot["checked"] == int(checked * 1000)
            assert snapshot["attempted"] == int(clock() * 1000)
            assert kernels(ksp, "rhel9")  # Last good data is still served.
            assert snapshot["pageUpdated"] == "November 18, 2026, 12:16 UTC"
            # Backoff: no new attempt until the pause has passed.
            clock.now += 30
            assert not ksp.due()
            clock.now += 31
            assert ksp.due()
            cache.close()

    asyncio.run(run())


def test_api_returns_the_contract_shape(tmp_path):
    clock = Clock()
    settings = Settings(admin_port=None, rate_limit_requests=0)
    with TestClient(create_app(tmp_path / "api.sqlite3", clock=clock, background=False, settings=settings)) as client:
        client.app.state.ksp.store(parse(FIXTURE), clock())
        response = client.get("/api/tmds", headers={"Accept-Encoding": "gzip"})
        body = response.json()
        assert response.headers["cache-control"] == "no-store"
        assert body["enabled"] is True
        assert set(body) >= {"products", "error", "attempted", "checked", "source", "ksp"}
        ksp = body["ksp"]
        assert ksp["source"] == PAGE
        assert set(ksp) == {"products", "error", "attempted", "checked", "source", "pageUpdated", "notes"}
        entry = ksp["products"]["rhel9"][1]
        assert entry["architecture"] == "x86_64"
        assert set(entry) == {"architecture", "platform", "filename", "release", "download", "sha256", "kernels"}
        assert entry["kernels"][0] == ["5.14.0-70.13.1.el9_0.x86_64", "default", None, False]


def test_tmds_disabled_starts_no_jobs_and_reports_disabled(tmp_path):
    settings = Settings(admin_port=None, tmds_enabled=False)
    with TestClient(create_app(tmp_path / "off.sqlite3", settings=settings)) as client:
        assert client.get("/api/tmds").json() == {"enabled": False}
        assert set(client.app.state.workers) == {"refresh"}
        assert client.get("/api/config").json()["tmds"] is False
