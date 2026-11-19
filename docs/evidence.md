# Evidence, caching and source semantics

This page explains how Is It Fixed turns vendor documents into the statuses shown in a case, and how the server caches and
refreshes them. It is the reference for "why does this row say X".

## Statuses

- **No data** means no vendor evidence was found for that product. It never means "not affected".
- **Inconclusive** means evidence exists but does not support a clear assessment.
- **Fix available** highlights a published fix. It does not claim the fix is installed, or that every component or
  service pack is fixed.
- Distribution status is never inferred from upstream package status, and unaffected version ranges are never read as
  fixed releases.

## Per-vendor semantics

| Vendor    | Source                                         | Semantics                                                                                                                                                                                                                                                                                                                                                                              |
| --------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Red Hat   | CSAF 2.0 / VEX, one document per CVE           | Product-tree relationships and product- or group-scoped remediations are evaluated.                                                                                                                                                                                                                                                                                                    |
| SUSE      | CSAF 2.0 / VEX, one document per CVE           | `recommended` builds count as fixed only when covered by a vendor-fix remediation. Service-pack context stays in the evidence. Advisory references are shown at document scope rather than assigned to every package. Public-cloud container-host images ("CHOST Images for …") are separate products: they are left out of the SLES OS rows and their count is shown with the source. |
| Ubuntu    | Ubuntu CVE tracker JSON, one document per CVE  | Pending uploads remain affected rather than counting as published fixes.                                                                                                                                                                                                                                                                                                               |
| Debian    | Debian security tracker JSON (bulk)            | A resolved entry with fixed version `0` means not affected. Debian 11 (Bullseye) is not offered: its LTS ended in August 2026 and the tracker no longer lists it; saved selections drop it automatically.                                                                                                                                                                              |
| Alpine    | Alpine secdb (bulk, fix records only)          | Absence from this fix-only feed does not establish unaffected status.                                                                                                                                                                                                                                                                                                                  |
| Microsoft | CVE record (CNA statement and affected builds) | Fixed Windows builds come from the CVE record. A dedicated Microsoft feed adapter is not implemented; CSAF documents can be imported manually.                                                                                                                                                                                                                                         |

A vendor that answers HTTP 404 for a per-CVE document (Red Hat, SUSE, Ubuntu) is reported as **not published** on that
source, not as an outage; the affected products stay **No data**.

## Fetching and refreshing

- A newly opened CVE is fetched on demand; fresh results are served from the SQLite cache.
- The server refreshes watched CVEs hourly, including while no browser is open. It checks for due work and expired data
  every minute and catches up after a restart.
- Selecting an additional vendor family fetches only that family and does not reset the hourly refresh clock.
- Each source has a time limit (30 seconds for per-CVE documents, 150 seconds for bulk feeds), so one slow vendor cannot
  hold up a response.
- Results stream to the browser as each area completes (`/api/cves/<id>/stream`, newline-delimited JSON).
- Bulk Debian and Alpine documents are kept in server memory for at most an hour; only normalized per-CVE results are
  stored.
- When the operator enables `MANUAL_REFRESH`, **Refresh data** forces an upstream refresh. Repeated requests share a
  60-second cooldown, and concurrent requests for the same CVE share one refresh. When it is disabled (the default), the
  button is hidden and the server rejects forced refreshes.

## Source failures

- A failing source keeps its previous evidence with the original timestamps and shows a short warning.
- Error messages are short and sanitized (for example "Vendor source unavailable: request timed out"). A source that
  failed repeatedly is paused for a while and says when it will be tried again.
- If the CVE record and all vendor evidence are unavailable, the API returns an error instead of an empty, seemingly
  safe result: 404 when the CVE Program has no such ID, 502 when sources failed.
- Lookups that return neither a CVE record nor vendor evidence are not stored, so unknown IDs cannot fill the cache.

## Watches and retention

- Saved browser cases are registered as watches under an anonymous workspace ID. Only CVE IDs and selected vendor
  families are sent. Case state, notes and read/unread markers stay in the browser.
- Deleting or archiving a case removes it from the workspace's watches. Restoring a backup replaces the workspace's
  watch set with the restored cases.
- **The 10-day retention clock starts when the last workspace stops watching a CVE.** Watched CVEs do not expire. If
  another workspace still watches the same CVE, its cache stays active.
- Unwatched data is no longer refreshed. Reads and refreshes do not extend its deadline; watching it again cancels the
  deadline. After 10 days the data is removed on the next cleanup pass (within about a minute); expired data is never
  served.
- Workspaces whose watches have not been synced for `WORKSPACE_TTL_DAYS` (default 30) are dropped, which starts the
  retention clock for CVEs nobody else watches. The open app re-syncs every 5 minutes.
- When the cache is full, the least recently refreshed unwatched CVE is removed early. Watched CVEs are never evicted.
- The SQLite database uses secure deletion and no persistent write-ahead log, so deleted cache content is not kept in
  the database files.
- Retention applies to the server cache. Browser data and exported backups stay until the user removes them.
  Operator-managed database backups and reverse-proxy logs need their own retention settings.

## Browser storage

Cases, product selections, source snapshots, settings and the workspace ID are stored in the browser's IndexedDB for
this site. Storage is per browser and origin, unencrypted, and can be cleared by the browser or the user. Once the
workspace holds a case, the app asks the browser to keep this site's storage persistent, which exempts it from automatic
eviction when the device is low on space; browsers may grant this silently, ask (Firefox), or decline. Persistent storage
does not stop the user from clearing site data and has no expiry. Export a backup
from Settings to keep a copy; restoring replaces the workspace after confirmation. Legacy notes and imported evidence in
old backups are preserved, but their editing controls have been removed.

## Test fixtures

Reduced public source excerpts under [`tests/fixtures/`](../tests/fixtures/README.md) are test data only.
