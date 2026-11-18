# CVE Desk

A compact CVE case workspace: a static frontend with browser-local cases, backed by a small FastAPI vendor-data cache.

## Run

Use Docker with the Compose plugin:

```sh
docker compose up --build -d
```

Open http://localhost:8080. Compose binds to localhost, restarts the app automatically, and checks `/api/health`. FastAPI serves the frontend and API from the same origin. One worker runs the hourly refresh jobs and SQLite cache.

```sh
docker compose logs -f app
docker compose down
```

The existing `data/` directory is mounted at `/data`, preserving cached evidence, agent inventories and watch registrations across rebuilds and container replacement. Stopping Compose does not delete it. Browser cases and settings remain in browser storage. No host Python environment or Node installation is needed to run the app.

To update after pulling changes, run `docker compose up --build -d` again. HTTPS is recommended outside localhost and required for desktop notifications. Put a reverse proxy in front if remote access is needed.

### Separate static hosting

The frontend can still be hosted separately. Set `API_BASE` in `src/config.js` to the backend URL, for example `https://cve-api.example.com/api`. Set `CORS_ORIGINS=https://cve.example.com` on the backend (comma-separated exact origins), and optionally `SERVE_FRONTEND=false`. A reverse proxy routing `/api` to FastAPI also works without changing `API_BASE`.

Only explicit frontend directories/files are served; backend source, SQLite files, and repository contents are not exposed by a root static mount. The API fetches fixed official source URLs, not caller-supplied URLs. It has no user authentication; restrict access at your reverse proxy if this is a private deployment. It accepts up to 1,000 watched CVEs globally and keeps up to 1,000 cached CVEs. When the cache is full, the least recently refreshed unwatched CVE is removed early; watched CVEs are never evicted. Lookups that return no CVE record and no vendor evidence are not stored, so unknown IDs cannot fill the cache. The frontend uses system fonts and loads no third-party assets.

## Watching, refreshing and retention

Saved browser cases register as watches under an anonymous workspace ID stored in localStorage. Only CVE IDs and selected vendor families are sent to the backend. Complete case state and read/unread indicators stay in the browser.

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

A vendor answering 404 for a per-CVE document (Red Hat, SUSE, Ubuntu) is reported as `notPublished` on that source, not as an outage; affected products stay **No data**. Each source has a time limit (30 seconds for per-CVE documents, 150 seconds for bulk feeds), so one slow vendor cannot hold up a response indefinitely. Selecting an additional vendor family fetches only that family and does not reset the hourly refresh clock.

## API

- `GET /api/health`
- `GET /api/cves/CVE-2026-98432?families=rhel,sles&refresh=false`
- `PUT /api/workspaces/<workspace-uuid>/watches` with `{"cases":[{"id":"CVE-2026-98432","families":["rhel","sles"]}]}`

The watch request replaces that workspace's complete set. Send `{"cases":[]}` to stop all its watches. Accepted vendor families are `rhel`, `sles`, `debian`, `ubuntu`, and `alpine`. An empty family selection still retrieves the CVE record. Windows currently uses CVE CNA statements or manually imported CSAF; its independent feed adapter is not implemented.

Case responses contain the CVE record, normalized `vendorData.evidence`, per-source URLs/fetch timestamps/errors, and cache/watch metadata. The GET endpoint alone does not register a watch. API responses use `Cache-Control: no-store` so browser HTTP caching does not hide server updates.

## Evidence

OS selection groups Red Hat, Debian, SUSE, Microsoft, Ubuntu and Alpine with logos and explicit versions. Missing evidence is **No data**, never “not affected.” Distribution status is not inferred from upstream package status. Unaffected version ranges are not inferred to be fixed releases. **Fix available** highlights a published fix without claiming it is installed or that every component/service pack is fixed.

- Red Hat and SUSE: CSAF 2.0/VEX, including product-tree relationships and product/group-scoped remediations. SUSE `recommended` builds count as fixed only when covered by a vendor-fix remediation. Service-pack context stays in the evidence. SUSE advisory references are shown at document scope rather than assigned to every package. SUSE public-cloud container-host images ("CHOST Images for …") are separate products; they are left out of the SLES OS rows and their count is shown with the source.
- Ubuntu: tracker JSON. Pending uploads remain affected, rather than published fixes.
- Debian: tracker JSON. A resolved entry with fixed version `0` means unaffected. Debian 11 (Bullseye) is not offered: its LTS ended in August 2026 and the tracker no longer lists it. Saved selections drop it automatically.
- Alpine: secdb fix records. Absence in this fix-only feed does not establish unaffected status.

Source links open in new tabs. The EUVD link opens its search homepage. Legacy notes and imported evidence in old backups are preserved, but their editing controls have been removed.

The old static `vendor-data/` cache, watchlist, feed-sync script and committing workflow have been retired. Vendor cache data no longer needs to be pushed or redeployed. Reduced public source excerpts under `tests/fixtures/` are test data only.

## Checks

Development tooling uses [uv](https://docs.astral.sh/uv/) for Python and [pnpm](https://pnpm.io/) for the JavaScript linters; both only resolve dependency releases that are at least two days old.

```sh
uv sync                              # Python runtime and dev dependencies (.venv)
pnpm install                         # prettier and eslint
uv run pytest                        # backend tests
pnpm test                            # frontend tests (node --test)
uv run ruff check && uv run ruff format --check
pnpm lint && pnpm format:check
uv run pre-commit install            # optional: run all checks on commit
```

To skip the bulk reformatting commit in `git blame`, run `git config blame.ignoreRevsFile .git-blame-ignore-revs`.

Backend tests cover explicit/shared watches, ten-day expiry, rewatching, restart persistence, closed-browser refresh, concurrent lookups, cooldown, failed sources, validation, private-file routing and vendor parsing. JavaScript tests cover assessment, source semantics, sidebar updates and the browser/API contract. `pnpm check` checks frontend syntax.

Sources: [CVE Program](https://www.cve.org/), [Red Hat VEX](https://security.access.redhat.com/data/csaf/v2/vex/), [SUSE CSAF/VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/), [Ubuntu tracker](https://ubuntu.com/security/cves), [Debian tracker](https://security-tracker.debian.org/tracker), [Alpine secdb](https://secdb.alpinelinux.org/). Red Hat and SUSE source data are licensed under CC BY 4.0; the cache normalizes those documents. See [logo attribution](assets/logos/README.md) and [fixture attribution](tests/fixtures/README.md). No analytics.

## Case layout and progressive loading

Settings controls default versions, OS ordering and the appearance (follow the system, light or dark). Version pickers are collapsed independently of their selections; removing the last selection does not collapse a picker. Cases group results in collapsible OS sections. New vendor selections fetch data automatically. Refresh streams completed CVE/vendor areas over `/api/cves/<id>/stream` as newline-delimited JSON, while the existing snapshot endpoint remains available. Source errors preserve saved evidence. Missing evidence is **No data**; evidence without a conclusive assessment is **Inconclusive**.

## Trend Micro LTS 20 inventory

A separate worker checks the official download-center JSON hourly. It downloads the latest enabled LTS 20 agent ZIP for each supported OS/architecture stream, validates the published SHA-256, and records bundled `Plugin-VFS_Filter_<kernel>` descriptors. Archives are inspected in memory and never executed or extracted onto disk; downloads are limited to 300 MiB. No agent binaries are persisted. SQLite stores release metadata, checksums, source URLs and kernel descriptor names. Superseded inventory expires ten days after it was last current; current releases stay retained. Failed checks preserve unexpired inventory and expose an error through `/api/tmds`.

The initial inventory may take several minutes to populate. Existing releases are not downloaded again. Initial discovery starts with the current release per stream; it does not backfill all historical binaries. Kernel fixes show exact matching bundled descriptor entries and their OS/architecture-specific agent version. Missing matches remain unverified: distro source-package versions may differ from kernel ABI names, and separately delivered kernel support packages are outside this bundled inventory. Descriptor presence is package evidence, not a runtime certification or a statement about an installed agent.
