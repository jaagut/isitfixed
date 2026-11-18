import asyncio
import hashlib
import io
import zipfile

import httpx
import pytest

from backend import tmds
from backend.cache import RETENTION, Cache
from backend.tmds import Inventory, inspect_archive


def test_vfs_inventory_requires_checksum_and_vfs_descriptor():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("Plugin-VFS_Filter_6_1_0_53_amd64-Debian_12-20.0.3-28120.x86_64.dsp", "descriptor")
        archive.writestr("Plugin-Filter_6_1_0_54_amd64-Debian_12-20.0.3-28120.x86_64.dsp", "different module")
    card = dict(platform="Debian_12", release="20.0.3-28120", sha256=hashlib.sha256(data.getvalue()).hexdigest())
    assert inspect_archive(data.getvalue(), card) == ["6_1_0_53_amd64"]
    with pytest.raises(ValueError, match="checksum"):
        inspect_archive(data.getvalue() + b"changed", card)


def test_inventory_expiry_is_enforced_on_reads(tmp_path):
    cache = Cache(tmp_path / "agents.sqlite")
    inventory = Inventory(cache, None, lambda: RETENTION + 100)
    cache.db.execute("INSERT INTO agents VALUES (?,?,?,?)", ("old.zip", "debian12", "{}", 100))
    cache.db.commit()
    assert inventory.snapshot()["products"] == {}
    cache.close()


def agent_zip():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("Plugin-VFS_Filter_5_14_0_70_x86_64-RedHat_EL9-20.0.3-1.x86_64.dsp", "descriptor")
    return data.getvalue()


def feed(archive, filename="Agent-RedHat_EL9-20.0.3-1.x86_64.zip"):
    card = dict(
        filename=filename,
        release="20.0.3-1",
        platform="RedHat_EL9",
        majorMinor="20.0",
        releaseTimestamp=1,
        releaseDate="Oct 28, 2026",
        download=f"https://files.trendmicro.com/products/deepsecurity/en/20.0/{filename}",
        sha256=hashlib.sha256(archive).hexdigest(),
    )
    return [{"name": "Agent", "cards": [card]}]


def test_agents_are_spooled_inspected_and_recorded(tmp_path, monkeypatch):
    archive = agent_zip()
    monkeypatch.setattr(tmds, "SPOOL_IN_MEMORY", 16)  # Force the on-disk spool path.

    async def handler(request):
        if request.url.path.endswith(".json"):
            return httpx.Response(200, json=feed(archive))
        return httpx.Response(200, content=archive)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cache = Cache(tmp_path / "agents.sqlite")
            inventory = Inventory(cache, client, lambda: 1790000000.0)
            await inventory.tick()
            snapshot = inventory.snapshot()
            assert snapshot["error"] is None and snapshot["checked"] == 1790000000000
            [entry] = snapshot["products"]["rhel9"]
            assert entry["kernels"] == ["5_14_0_70_x86_64"] and entry["architecture"] == "x86_64"
            cache.close()
            # Status survives a restart, so the feed is not fetched again within the hour.
            cache = Cache(tmp_path / "agents.sqlite")
            assert not Inventory(cache, client, lambda: 1790000000.0 + 60).due()
            cache.close()

    asyncio.run(run())


def test_oversized_agent_download_is_rejected_with_a_clean_error(tmp_path, monkeypatch):
    archive = agent_zip()
    monkeypatch.setattr(tmds, "AGENT_LIMIT", 10)

    async def handler(request):
        if request.url.path.endswith(".json"):
            return httpx.Response(200, json=feed(archive))
        return httpx.Response(200, content=archive)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cache = Cache(tmp_path / "agents.sqlite")
            inventory = Inventory(cache, client, lambda: 1790000000.0)
            await inventory.tick()
            assert inventory.snapshot()["error"] == "response too large"
            assert inventory.snapshot()["checked"] is None
            cache.close()

    asyncio.run(run())


def test_worker_loop_survives_unexpected_errors(tmp_path):
    cache = Cache(tmp_path / "agents.sqlite")

    class Flaky(Inventory):
        pause = 0
        calls = 0

        async def tick(self):
            Flaky.calls += 1
            if Flaky.calls < 3:
                raise RuntimeError("bug")

    async def run():
        inventory = Flaky(cache, None, lambda: 0.0)
        task = asyncio.create_task(inventory.worker())
        for _ in range(100):
            await asyncio.sleep(0)
            if Flaky.calls >= 3:
                break
        assert not task.done() and Flaky.calls >= 3
        task.cancel()

    asyncio.run(run())
    cache.close()
