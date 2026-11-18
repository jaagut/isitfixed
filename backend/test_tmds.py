import hashlib
import io
import zipfile

import pytest

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
