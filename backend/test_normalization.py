"""Vendor status semantics kept by normalization, checked against reduced real vendor documents (backend/fixtures)."""

import json
from pathlib import Path

from backend.feedindex import debian_index
from backend.providers import csaf, debian, debian_codes, debian_evidence, ubuntu, ubuntu_note

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def test_red_hat_no_fix_reasons_become_notes_and_boilerplate_is_not_a_mitigation():
    rows, _ = csaf(load("redhat-cve-2023-52425.json"), "CVE-2023-52425", "rhel")
    by_name = {e["name"].split(" ")[0]: e for e in rows["rhel8"]}
    assert by_name["firefox"]["status"] == "affected"
    assert by_name["firefox"]["note"] == "Will not fix"
    # Plain "Affected" (none_available) restates the status and adds no note.
    assert "note" not in by_name["thunderbird"]
    # "Mitigation for this issue is either not available or …" is Red Hat's statement that there is none.
    assert all(not e["mitigation"] for e in rows["rhel8"])
    fixed = by_name["xmlrpc-c-0:1.51.0-9.el8_10.x86_64"]
    assert fixed["status"] == "fixed" and fixed["links"] == ["https://access.redhat.com/errata/RHSA-2024:4259"]
    assert "note" not in fixed

    rows, _ = csaf(load("redhat-cve-2024-2511.json"), "CVE-2024-2511", "rhel")
    assert {(e["status"], e["note"]) for e in rows["rhel8"]} == {("affected", "Fix deferred")}


def test_ubuntu_links_notices_per_release_and_explains_statuses():
    rows = ubuntu(load("ubuntu-cve-2025-9230.json"), "CVE-2025-9230")
    focal = {e["name"]: e for e in rows["ubuntu2004"]}
    assert focal["openssl"]["status"] == "fixed"
    assert focal["openssl"]["fix"] == ["openssl 1.1.1f-1ubuntu2.24+esm1"]
    assert focal["openssl"]["links"] == ["https://ubuntu.com/security/notices/USN-7786-1"]
    assert focal["openssl"]["note"] == "Fix requires Ubuntu Pro (ESM Infra)"
    assert focal["nodejs"]["note"] == "Not affected: uses system openssl"
    jammy = {e["name"]: e for e in rows["ubuntu2204"]}
    assert jammy["openssl"]["note"] == "" and jammy["openssl"]["links"]
    assert (jammy["nodejs"]["status"], jammy["nodejs"]["note"]) == ("affected", "Vulnerable; no fix released yet")
    assert jammy["nodejs"]["links"] == []  # Notices only attach to released fixes.
    assert rows["ubuntu2604"] == []


def test_ubuntu_note_wording():
    assert ubuntu_note("needs-triage", "", "security") == "Not yet triaged by Ubuntu"
    assert ubuntu_note("DNE", "", "security") == ""
    assert ubuntu_note("pending", "5.4.0-247.267", "security") == "Fix pending in 5.4.0-247.267; not yet released"
    assert ubuntu_note("ignored", "end of standard support", "security") == (
        "Ubuntu will not fix this: end of standard support"
    )
    assert ubuntu_note("deferred", "", "security") == "Fix deferred by Ubuntu"
    assert ubuntu_note("not-affected", "5.2.4-1ubuntu1.1", "security") == "Not affected in 5.2.4-1ubuntu1.1"
    assert ubuntu_note("released", "5.15.0-138.148+fips1", "fips-updates") == "Fix requires Ubuntu Pro FIPS updates"


def test_debian_triage_qualifiers_survive_the_index():
    doc = load("debian-tracker-excerpt.json")
    notes = {}
    for cve in ("CVE-2026-119373", "CVE-2026-104086", "CVE-2026-125742", "CVE-2026-58052", "CVE-2026-110875"):
        rows = debian(doc, cve)
        notes[cve] = [(e["status"], e["note"]) for e in rows["debian12"] + rows["debian13"]]
    assert notes["CVE-2026-119373"] == [
        ("affected", ""),
        ("affected", "No security advisory planned (Minor issue); may be fixed in a point release"),
    ]
    assert notes["CVE-2026-104086"] == [("affected", "Rated unimportant by Debian; not fixed via security updates")]
    assert notes["CVE-2026-125742"] == [
        ("affected", "Fix postponed to a later update (Minor issue, revisit when spu is ready)")
    ]
    assert notes["CVE-2026-58052"][0][1].startswith("Debian will not fix this (Only affects Windows NTFS")
    assert notes["CVE-2026-110875"] == [("unknown", "Debian has not determined whether this release is affected")]
    assert debian(doc, "CVE-2026-0396")["debian12"][0]["note"] == (
        "Not covered by Debian security support in this release"
    )
    assert debian(doc, "CVE-2026-27205")["debian12"][0]["note"] == (
        "Fix scheduled for the next point release (Minor issue)"
    )


def test_debian_accepts_index_entries_from_an_older_indexer():
    index = debian_index(load("debian-tracker-excerpt.json"), debian_codes())
    entries = [entry[:5] for entry in index["CVE-2026-119373"]]
    rows = debian_evidence(entries)
    assert [e["status"] for e in rows["debian12"] + rows["debian13"]] == ["affected", "affected"]


def test_debian_advisories_link_the_release_fix_they_shipped():
    from backend.feedindex import debian_advisory_index

    index = debian_advisory_index((FIXTURES / "debian-advisories-excerpt.txt").read_text(), debian_codes())
    assert index["CVE-2024-6387"] == [["DSA-5724-1", "bookworm", "openssh", "1:9.2p1-2+deb12u3"]]
    assert "CVE-2016-0777" not in index  # releases other than the tracked ones are dropped
    entries = [
        ["openssh", "bookworm", "resolved", "1:9.2p1-2+deb12u3", None, None, "not yet assigned", False],
        ["openssh", "trixie", "resolved", "1:9.7p1-7", None, None, "not yet assigned", False],
    ]
    rows = debian_evidence(entries, index["CVE-2024-6387"])
    assert rows["debian12"][0]["links"] == ["https://security-tracker.debian.org/tracker/DSA-5724-1"]
    assert rows["debian13"][0]["links"] == []  # fixed before the release; no advisory
    kernel = [
        ["linux", "bookworm", "resolved", "6.1.190-1", None, None, "not yet assigned", False],
        ["linux", "trixie", "resolved", "6.12.113-1", None, None, "not yet assigned", False],
        ["linux-6.12", "bookworm", "resolved", "6.12.113-1~deb12u1", None, None, "not yet assigned", False],
    ]
    rows = debian_evidence(kernel, index["CVE-2026-98432"])
    assert [e["links"] for e in rows["debian12"]] == [
        ["https://security-tracker.debian.org/tracker/DLA-4841-1"],
        ["https://security-tracker.debian.org/tracker/DLA-4850-1"],
    ]
    assert rows["debian13"][0]["links"] == ["https://security-tracker.debian.org/tracker/DSA-6568-1"]
