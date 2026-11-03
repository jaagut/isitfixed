# CVE Desk

A static browser-local CVE case workspace. No build step, account, API key or backend.

Run `python3 -m http.server 8080`, then open http://localhost:8080. Deploy these files to any static host, including a subdirectory. Use HTTP rather than opening `index.html` through `file://`, because the app uses JavaScript modules. HTTPS or localhost is required for desktop notifications.

Cases, product selections, source snapshots, notes and activity are kept in localStorage. Export/restore JSON backups in workspace settings. Restore replaces the workspace after confirmation. Storage is per browser/origin, unencrypted, subject to clearing and quota; export regularly. Concurrent editing across tabs is not coordinated.

## Evidence and coverage

Automatic lookups use the public CVE Program API at `https://cveawg.mitre.org/api/cve/<CVE-ID>`. Assessments use explicit matching CNA product statements. Distribution status is never inferred from upstream status. Missing evidence is **Needs review**, never “not affected.” Unaffected versions are not inferred to be fixed releases. A published fix does not confirm installation. Affected components take precedence over fixed components.

OS selection groups Red Hat, Debian, SUSE, Microsoft, Ubuntu and Alpine by vendor, with explicit version choices and locally hosted logos. Old Python/PHP selections are removed automatically; old generic Windows selections expand into explicit Windows versions. Notes and cases are preserved.

Automatic vendor lookups first load same-origin `vendor-data/<CVE-ID>.json` snapshots. The feed-sync script produces these from official Red Hat and SUSE CSAF/VEX, Ubuntu tracker JSON, Debian tracker JSON and Alpine secdb. Red Hat product relationships retain OS context, fixed builds and advisory links. Ubuntu pending updates remain affected, not fixed. Alpine's fix-only feed cannot prove unaffected status from absence. SUSE CSAF/VEX is integrated for SLES 15 and 16. Microsoft currently uses CNA statements or manual CSAF/VEX import; its independent adapter is not implemented. Vendor links remain available. EUVD opens its search homepage.

### Static feed updates

Run `node scripts/sync-feeds.mjs CVE-2026-98432` to refresh a specific snapshot, or `node scripts/sync-feeds.mjs` to sync all IDs in `vendor-data/watchlist.json`. The included snapshot was generated from actual vendor documents and contains `kernel-5.14.0-687.64.1.el9_8` with `RHSA-2026:93412`. Source URLs, fetch times, failures and release context are retained.

The included GitHub Actions workflow runs hourly and commits successful feed updates. It must be pushed to a GitHub repository with Actions and workflow write permission enabled. Configure your static host to redeploy those commits. GitHub Pages deployments requiring an Actions workflow need their own deployment step; commits made with the Actions token do not trigger a separate Pages build. This session does not enable Actions or publish/deploy the app.

**Browser cases do not modify the server watchlist.** Add newly tracked CVEs to `vendor-data/watchlist.json` and deploy the generated snapshots to get automatic vendor evidence for them. The app attempts direct Red Hat/SUSE/Ubuntu/Alpine reads when a snapshot is absent or over an hour old, but current vendor endpoints omit CORS headers and commonly block browser reads. This cannot be bypassed by a static site. No third-party CORS proxy is used. Failed fetches preserve evidence with its original timestamp and display source warnings. Source timestamps are independent of the CVE record's last check time.

Manual CSAF 2.0 VEX import is still available. Imported evidence remains a snapshot and needs reimport to update. Imported evidence is combined with vendor evidence conservatively; any affected component keeps the product affected, in the underlying evidence. The main assessment badge instead highlights **Fix available** when a vendor publishes a fix, without implying every component is fixed or any patch is installed. Cases with available fixes continue hourly checking. A version choice is a scope, not a claim of current vendor support or an installed-package inventory.

Hourly checks run for unresolved cases while the page is open, with catch-up on returning to the tab or coming online. Closed pages cannot run reliable background checks, and browsers may throttle inactive tabs. Source changes move the case to the top of the sidebar with a persistent New indicator (cleared when opened), and optionally trigger desktop notifications; initial lookups do not notify. Network failures preserve the previous snapshot.

No runtime JavaScript dependencies or analytics. Optional Google Fonts fall back to system fonts offline. Source requests disclose queried CVE IDs to their providers.

### SUSE CSAF details

The connector uses `https://ftp.suse.com/pub/projects/security/csaf-vex/<year>/<cve-id-lowercase>.json`; CVEs predating 2023 are stored in the initial 2023 partition. The legacy flat `security-data.suse.com` directory is not used for current downloads.

CSAF product relationships retain SLES major-version and service-pack context. SUSE publishes patched builds under `recommended`; these count as fixed builds only when an explicit vendor-fix remediation covers that product. Product and group remediation scopes are respected. A recommended build without such a remediation stays unverified. Other affected service packs/components remain in the evidence.

The source's release timestamp and fetched timestamp are shown separately. SUSE's current per-CVE document lists advisory references at document scope; these appear under “Advisories in source document,” without assigning every advisory to every package. Importing a CSAF document uses the same status and remediation logic.

The included CVE-2026-98432 snapshot now contains SUSE evidence, and the existing hourly GitHub workflow syncs SUSE alongside the other configured feeds. It still requires deployment setup as described above. Browser fetch failures retain previous snapshots and source age.

## Checks

Run `node --test` for assessment and feed tests. `npm test`, `npm run check`, and `npm run sync-feeds` are aliases where npm is available. Tests cover conservative assessment, migration, vendor-specific release semantics, unavailable feeds, and the reported RHEL fix/advisory.

Sources: [CVE Program](https://www.cve.org/), [Red Hat VEX](https://security.access.redhat.com/data/csaf/v2/vex/), [SUSE CSAF/VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/), [Ubuntu security tracker](https://ubuntu.com/security/cves), [Debian security tracker](https://security-tracker.debian.org/tracker), [Alpine secdb](https://secdb.alpinelinux.org/). [Red Hat security data](https://access.redhat.com/security/data) and [SUSE CSAF data](https://www.suse.com/support/security/csaf/) are licensed under CC BY 4.0. The generated snapshots normalize the original vendor documents. Logos: [asset attribution](assets/logos/README.md).
