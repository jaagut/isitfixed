"""Compact bulk vendor feeds into per-CVE indexes.

The Debian security tracker dump is ~90 MB of JSON and decodes to several hundred MB of Python objects. The app runs
this module as a short-lived child process (``python -I -S feedindex.py debian <file> <codename>...``), so that peak
and the allocator fragmentation it leaves behind stay out of the long-running server; only the compact index (one
line per CVE: ``CVE-ID<TAB>[[package, codename, status, fixed_version, nodsa, nodsa_reason, urgency,
next_point_update], ...]``) comes back. The functions are also imported by the app. Standard library only: the child
runs without site-packages.
"""

import json
import re
import sys


def debian_index(doc, codes):
    """``{cve: [[package, codename, status, fixed_version, nodsa, nodsa_reason, urgency, next_point_update], ...]}``.

    Only the given release codenames are kept. ``nodsa_reason`` ("", "postponed" or "ignored"), ``urgency`` (such
    as "unimportant" or "end-of-life") and ``next_point_update`` qualify an open issue.
    """
    if not isinstance(doc, dict):
        raise ValueError("Debian tracker data is not an object")
    index = {}
    for package, records in doc.items():
        if not isinstance(records, dict):
            continue
        for cve, record in records.items():
            releases = record.get("releases") if isinstance(record, dict) else None
            if not isinstance(releases, dict):
                continue
            for code in codes:
                release = releases.get(code)
                if isinstance(release, dict):
                    entry = [
                        package,
                        code,
                        release.get("status"),
                        release.get("fixed_version"),
                        release.get("nodsa"),
                        release.get("nodsa_reason"),
                        release.get("urgency"),
                        bool(release.get("next_point_update")),
                    ]
                    index.setdefault(cve, []).append(entry)
    return index


ADVISORY_HEAD = re.compile(r"^\[[^\]]*\]\s+((?:DSA|DLA)-\d+(?:-\d+)?)\b")
ADVISORY_CVES = re.compile(r"^\s+\{([^}]*)\}")
ADVISORY_FIX = re.compile(r"^\s+\[(\w+)\]\s+-\s+(\S+)\s+([^\s<]\S*)\s*$")


def debian_advisory_index(text, codes):
    """``{cve: [[advisory, codename, package, version], ...]}`` from the tracker's data/DSA/list or data/DLA/list.

    Each advisory starts with ``[date] DSA-1234-1 package - title``, followed by ``{CVE-...}`` and one
    ``[codename] - package version`` line per fixed release; other lines (NOTE:, <not-affected>) are skipped.
    """
    index, current, cves = {}, None, []
    for line in text.splitlines():
        if head := ADVISORY_HEAD.match(line):
            current, cves = head[1], []
        elif current and (found := ADVISORY_CVES.match(line)):
            cves = [token for token in found[1].split() if token.startswith("CVE-")]
        elif current and (fix := ADVISORY_FIX.match(line)) and fix[1] in codes:
            for cve in cves:
                index.setdefault(cve, []).append([current, fix[1], fix[2], fix[3]])
    return index


def alpine_index(doc):
    """``{cve: [(package, version), ...]}`` from one Alpine secdb document."""
    index = {}
    for package in doc.get("packages", []):
        pkg = package["pkg"]
        for version, ids in pkg.get("secfixes", {}).items():
            found = {token for value in ids for token in value.split()}
            for cve in found:
                index.setdefault(cve, []).append((pkg["name"], version))
    return index


def main(argv):
    kind, path, *codes = argv
    if kind != "debian" or not codes:
        return 2
    try:
        with open(path, "rb") as source:
            index = debian_index(json.load(source), codes)
    except (ValueError, UnicodeDecodeError):
        return 3
    out = sys.stdout
    for cve, entries in index.items():
        if "\t" in cve or "\n" in cve:
            continue
        out.write(f"{cve}\t{json.dumps(entries, separators=(',', ':'))}\n")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
