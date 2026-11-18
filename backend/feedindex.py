"""Compact bulk vendor feeds into per-CVE indexes.

The Debian security tracker dump is ~90 MB of JSON and decodes to several hundred MB of Python objects. The app runs
this module as a short-lived child process (``python -I -S feedindex.py debian <file> <codename>...``), so that peak
and the allocator fragmentation it leaves behind stay out of the long-running server; only the compact index (one
line per CVE: ``CVE-ID<TAB>[[package, codename, status, fixed_version, nodsa], ...]``) comes back. The functions are
also imported by the app. Standard library only: the child runs without site-packages.
"""

import json
import sys


def debian_index(doc, codes):
    """``{cve: [[package, codename, status, fixed_version, nodsa], ...]}`` for the given release codenames."""
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
                    entry = [package, code, release.get("status"), release.get("fixed_version"), release.get("nodsa")]
                    index.setdefault(cve, []).append(entry)
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
