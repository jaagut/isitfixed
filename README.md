# CVE Desk

A compact CVE case workspace: a static frontend with browser-local cases and notes, backed by a small FastAPI vendor-data cache.

## Run

Python 3.11+ is required. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8080 --workers 1
```

Open http://localhost:8080. FastAPI serves the frontend assets and API from the same origin. API documentation is at `/docs`. No Node runtime, frontend build step, API key, or GitHub Actions feed job is needed. HTTPS is recommended outside localhost and required for desktop notifications.

The cache lives at `data/cache.sqlite3`, excluded from Git. Set `CACHE_DB` to change its location. Use one application worker: the hourly scheduler, request coalescing and bulk-feed cache run in that process. SQLite data and watch registrations survive restarts. Do not use `--reload` in production.

### Docker

```sh
docker build -t cve-desk .
docker run --rm -p 8080:8080 -v cve-desk-data:/data cve-desk
```

The `/data` volume holds the SQLite cache and watch registrations. Keep it across deployments.

### Separate static hosting

The frontend can still be hosted separately. Set `API_BASE` in `src/config.js` to the backend URL, for example `https://cve-api.example.com/api`. Set `CORS_ORIGINS=https://cve.example.com` on the backend (comma-separated exact origins), and optionally `SERVE_FRONTEND=false`. A reverse proxy routing `/api` to FastAPI also works without changing `API_BASE`.

Only explicit frontend directories/files are served; backend source, SQLite files, and repository contents are not exposed by a root static mount. The API fetches fixed official source URLs, not caller-supplied URLs. It has no user authentication; restrict access at your reverse proxy if this is a private deployment. It accepts up to 1,000 watched CVEs globally and keeps up to 1,000 cached CVEs. When the cache is full, the least recently refreshed unwatched CVE is removed early; watched CVEs are never evicted. Lookups that return no CVE record and no vendor evidence are not stored, so unknown IDs cannot fill the cache. The frontend uses system fonts and loads no third-party assets.

## Watching, refreshing and retention

Saved browser cases register as watches under an anonymous workspace ID stored in localStorage. Only CVE IDs and selected vendor families are sent to the backend. Notes, complete case state, local imports, and read/unread indicators stay in the browser.

- Newly opened CVEs are fetched on demand. Fresh results are served from SQLite.
- The backend refreshes watched CVEs hourly, including while the browser is closed. It checks for due work and expired data every minute, and catches up after a restart.
- **Refresh data** asks the backend to refresh upstream sources. Repeated manual requests share a 60-second cooldown; concurrent requests for the same CVE share one refresh.
- Browser checks run hourly while open and on returning to the tab. Source changes mark a case **New** and move it to the sidebar's top. Opening it clears the marker. Optional desktop notifications require permission.
- Deleting a case removes this workspace's watch. Restore replaces this workspace's watch set with the restored cases.
- **The ten-day retention clock starts when the last workspace stops watching a CVE.** Watched CVEs have no expiry. If another workspace still watches the same CVE, its cache remains active.
- Unwatched data is no longer refreshed in the background. Reads and refreshes do not extend its retention deadline. Rewatching before expiry cancels that deadline. After ten days unwatched, cache data is removed on the next cleanup pass (at most about a minute later); expired data is never served.
- Watch registrations persist until explicitly removed by the workspace. Clearing browser storage alone does not unregister server watches. Delete cases before clearing storage; the watch endpoint below can also clear a known workspace's registrations. Workspace IDs should be kept private because they authorize replacing that watch set.

The retention policy applies to backend cache data. Browser snapshots and exported backups persist until the user removes them. Operator-managed database backups and access logs require their own retention configuration. The SQLite connection uses secure deletion and a non-WAL journal to avoid keeping old cache contents in a persistent WAL file.

Bulk Debian/Alpine documents are shared in server memory for at most an hour; only normalized per-CVE results are persisted. Source failures preserve prior evidence and its original timestamps, with explicit warnings. If a CVE record and all vendor evidence are unavailable, the API returns an error rather than a safe assessment: 404 when the CVE Program has no such ID, 502 when sources failed.

A vendor answering 404 for a per-CVE document (Red Hat, SUSE, Ubuntu) is reported as `notPublished` on that source, not as an outage; affected products stay **Needs review**. Each source has a time limit (30 seconds for per-CVE documents, 150 seconds for bulk feeds), so one slow vendor cannot hold up a response indefinitely. Selecting an additional vendor family fetches only that family and does not reset the hourly refresh clock.

## API

- `GET /api/health`
- `GET /api/cves/CVE-2026-98432?families=rhel,sles&refresh=false`
- `PUT /api/workspaces/<workspace-uuid>/watches` with `{"cases":[{"id":"CVE-2026-98432","families":["rhel","sles"]}]}`

The watch request replaces that workspace's complete set. Send `{"cases":[]}` to stop all its watches. Accepted vendor families are `rhel`, `sles`, `debian`, `ubuntu`, and `alpine`. An empty family selection still retrieves the CVE record. Windows currently uses CVE CNA statements or manually imported CSAF; its independent feed adapter is not implemented.

Case responses contain the CVE record, normalized `vendorData.evidence`, per-source URLs/fetch timestamps/errors, and cache/watch metadata. The GET endpoint alone does not register a watch. API responses use `Cache-Control: no-store` so browser HTTP caching does not hide server updates.

## Evidence

OS selection groups Red Hat, Debian, SUSE, Microsoft, Ubuntu and Alpine with logos and explicit versions. Missing evidence is **Needs review**, never “not affected.” Distribution status is not inferred from upstream package status. Unaffected version ranges are not inferred to be fixed releases. **Fix available** highlights a published fix without claiming it is installed or that every component/service pack is fixed.

- Red Hat and SUSE: CSAF 2.0/VEX, including product-tree relationships and product/group-scoped remediations. SUSE `recommended` builds count as fixed only when covered by a vendor-fix remediation. Service-pack context stays in the evidence. SUSE advisory references are shown at document scope rather than assigned to every package. SUSE public-cloud container-host images ("CHOST Images for …") are separate products; they are left out of the SLES OS rows and their count is shown with the source.
- Ubuntu: tracker JSON. Pending uploads remain affected, rather than published fixes.
- Debian: tracker JSON. A resolved entry with fixed version `0` means unaffected. Debian 11 (Bullseye) is not offered: its LTS ended in August 2026 and the tracker no longer lists it. Saved selections drop it automatically.
- Alpine: secdb fix records. Absence in this fix-only feed does not establish unaffected status.

Manual CSAF/VEX import remains available. Local imports stay in browser storage and need manual reimport. Vendor evidence and local imports are combined conservatively in the underlying evidence. Source links open in new tabs. The EUVD link opens its search homepage.

The old static `vendor-data/` cache, watchlist, feed-sync script and committing workflow have been retired. Vendor cache data no longer needs to be pushed or redeployed. Reduced public source excerpts under `tests/fixtures/` are test data only.

## Checks

```sh
.venv/bin/python -m pip install -r backend/requirements-dev.txt
.venv/bin/python -m pytest backend -q
node --test
```

Backend tests cover explicit/shared watches, ten-day expiry, rewatching, restart persistence, closed-browser refresh, concurrent lookups, cooldown, failed sources, validation, private-file routing and vendor parsing. JavaScript tests cover assessment, source semantics, sidebar updates and the browser/API contract. `npm run check` checks frontend syntax where npm is available.

Sources: [CVE Program](https://www.cve.org/), [Red Hat VEX](https://security.access.redhat.com/data/csaf/v2/vex/), [SUSE CSAF/VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/), [Ubuntu tracker](https://ubuntu.com/security/cves), [Debian tracker](https://security-tracker.debian.org/tracker), [Alpine secdb](https://secdb.alpinelinux.org/). Red Hat and SUSE source data are licensed under CC BY 4.0; the cache normalizes those documents. See [logo attribution](assets/logos/README.md) and [fixture attribution](tests/fixtures/README.md). No analytics. Optional Google Fonts fall back to system fonts offline.
