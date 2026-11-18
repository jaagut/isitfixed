# CVE Desk

CVE Desk is a small, self-hostable workspace for tracking individual CVEs across Linux distributions and Windows. Open a
case for a CVE, pick the OS versions you run, and see per-version vendor status, published fixes and advisories in one
place. The server keeps the vendor data current; your cases stay in your browser.

<!-- Screenshot: add docs/screenshot.png here once a public instance exists. -->

> **Disclaimer.** CVE Desk is an informational tool. Data comes from public vendor sources and may be incomplete,
> delayed or wrong. No warranty — use at your own discretion and verify with the vendor before acting. Not affiliated
> with or endorsed by Red Hat, SUSE, Canonical, Debian, Alpine, Microsoft or Trend Micro.

## Features

- **One case per CVE.** CVE record, CVSS scores, vendor status per OS version, fixed packages, advisories and
  mitigations, with links to the vendor pages.
- **Vendor evidence** from Red Hat (CSAF/VEX), SUSE (CSAF/VEX), Ubuntu, Debian and Alpine, plus Microsoft fixed builds
  from the CVE record. Missing evidence is shown as **No data**, never as "not affected".
- **Stays current, without noise.** The server refreshes every watched CVE hourly, also while your browser is closed.
  Cases are marked **New** (with optional desktop notifications) only for changes worth acting on: a status change, a
  newly published fix or mitigation, TMDS Agent or Kernel Support Package support becoming available, or a rejected CVE.
  Source timestamps alone never notify. A **Sources** section on each case shows when every source was last checked.
- **Trend Micro Deep Security (TMDS) Agent matching.** For kernel fixes, shows whether the current LTS 20 agent or a
  Kernel Support Package lists the fixed kernel. Can be switched off per user or per server.
- **Private by design.** No account, no cookies, no analytics, no third-party resources. Cases live in your browser's
  local storage; export and restore JSON backups.
- **Case links** (`/CVE-2024-3094`), archive, search, light and dark theme.

## Quick start

Requirements: Docker with the Compose plugin.

```sh
git clone https://github.com/jaagut/cve-viewer.git
cd cve-viewer
docker compose up --build -d
```

Open <http://localhost:8080>. The app and API are served from one container. Data (SQLite cache, watch registrations,
agent inventory, logs) is stored in `./data`, mounted at `/data`, and survives rebuilds. Your cases and settings stay in
your browser.

```sh
docker compose logs -f app   # follow logs
docker compose up --build -d # update after git pull
docker compose down          # stop (keeps ./data)
```

A prebuilt image is published as `ghcr.io/jaagut/cve-viewer` (tags `latest`, `X.Y.Z`, `main`, `sha-<commit>`). For
public hosting behind a reverse proxy (HTTPS, trusted proxy IPs, imprint and privacy pages, admin dashboard), read
[docs/deployment.md](docs/deployment.md) and [docs/operations.md](docs/operations.md). HTTPS is required for desktop
notifications outside `localhost`.

## Configuration

All settings are environment variables. The most important ones are listed here; the full reference with all defaults
is in [docs/deployment.md](docs/deployment.md).

| Variable                                    | Default               | Purpose                                                                   |
| ------------------------------------------- | --------------------- | ------------------------------------------------------------------------- |
| `CACHE_DB`                                  | `/data/cache.sqlite3` | SQLite database for the vendor cache and watch registrations              |
| `SITE_URL` / `SOURCE_URL`                   | – / this repository   | Public URL of this instance / link to the source code shown in the footer |
| `MANUAL_REFRESH`                            | `false`               | Show the **Refresh data** button and allow forced upstream refreshes      |
| `TMDS_ENABLED`                              | `true`                | Run the Trend Micro agent and Kernel Support Package inventory jobs       |
| `MAX_WATCHED_CVES` / `MAX_CACHED_CVES`      | `1000` / `1000`       | Global caps for watched and cached CVEs                                   |
| `MAX_WATCHES_PER_WORKSPACE`                 | `200`                 | Cases one browser workspace may watch                                     |
| `WORKSPACE_TTL_DAYS`                        | `30`                  | Drop watch registrations of workspaces not seen for this many days        |
| `RATE_LIMIT_REQUESTS`                       | `240`                 | Requests per minute per client (`0` disables a limit)                     |
| `RATE_LIMIT_LOOKUPS` / `RATE_LIMIT_WATCHES` | `20` / `12`           | CVE lookups / watch syncs per minute per client                           |
| `RATE_LIMIT_LOOKUPS_GLOBAL`                 | `120`                 | CVE lookups per minute across all clients                                 |
| `FORWARDED_ALLOW_IPS`                       | `127.0.0.1`           | Reverse proxy IPs trusted for `X-Forwarded-For`                           |
| `LOG_DIR` / `LOG_LEVEL`                     | – / `INFO`            | Application log directory (the image uses `/data/logs`) and level         |
| `LOG_RETENTION_DAYS`                        | `14`                  | Log retention (maximum 14)                                                |
| `ADMIN_PORT` / `ADMIN_TOKEN`                | `8081` / –            | Private admin dashboard port (empty or `0` disables) and optional token   |
| `CORS_ORIGINS` / `CSP_CONNECT_SRC`          | –                     | Only needed when the frontend and API are hosted on different origins     |
| `LEGAL_OPERATOR_*`, `LEGAL_*`, `LEGAL_DIR`  | –                     | Imprint and privacy pages, see [legal/README.md](legal/README.md)         |

Advanced options (`SERVE_FRONTEND`, `FRONTEND_DIR`, `API_DOCS`, `HSTS`, `USER_AGENT`, `WATCHDOG_TIMEOUT`, `HOST`,
`PORT`) are described in the deployment docs.

## How it works

CVE Desk uses a pull model. Nothing is pushed to your browser.

1. **Your browser** stores cases, selections, settings and an anonymous random workspace ID in local storage. When you
   open a case, it asks the server for that CVE and the selected vendor families.
2. **The server** fetches the CVE record and vendor documents on demand, normalizes them and caches the result in
   SQLite. Saved cases are registered as _watches_ (CVE ID + vendor families) under the anonymous workspace ID.
3. **Every hour** the server refreshes all watched CVEs from the vendor sources, including while no browser is open.
4. **While open**, the browser checks its cases hourly and when you return to the tab; changes are marked **New**.

Retention, in short:

- Watched CVEs are kept and refreshed as long as at least one workspace watches them.
- When the last workspace stops watching a CVE, its cached data is deleted **10 days** later. Reading it does not extend
  that deadline; watching it again cancels it.
- Deleting or archiving a case removes it from your workspace's watches. Workspaces not seen for **30 days** are dropped
  automatically (the open app re-syncs every few minutes).
- Your browser data stays until you delete it. Export a backup before clearing browser storage.

Details on evidence semantics, source failures and the API: [docs/evidence.md](docs/evidence.md) and
[docs/api.md](docs/api.md).

## Privacy

- No cookies, tracking, analytics or third-party resources; fonts are system fonts and all assets are served locally.
- Browser local storage only, for things the app needs to work: cases, settings, the disclaimer acknowledgement and the
  anonymous workspace ID.
- The server stores only CVE IDs and selected vendor families per anonymous workspace ID, plus cached public vendor
  data. No names, accounts or e-mail addresses.
- Workspaces expire after 30 days of inactivity; unwatched cache data after 10 days; logs after at most 14 days.
- IP addresses are never stored or logged by the application. Rate limiting uses an HMAC of the client IP with an
  in-memory key that rotates daily and is never written to disk.
- Outbound requests go only to fixed official vendor URLs, never to URLs supplied by users.

Operators publish their own imprint and privacy policy; German templates with English translations are in
[legal/](legal/README.md).

## Sources and licenses

| Source                                                                      | Used for                                     | License / terms                                          |
| --------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------- |
| [CVE Program](https://www.cve.org/) (cveawg.mitre.org)                      | CVE record, CNA statements, Microsoft builds | [CVE terms of use](https://www.cve.org/Legal/TermsOfUse) |
| [Red Hat CSAF/VEX](https://security.access.redhat.com/data/csaf/v2/vex/)    | RHEL status, fixes, advisories               | CC BY 4.0                                                |
| [SUSE CSAF/VEX](https://ftp.suse.com/pub/projects/security/csaf-vex/)       | SLES status, fixes, advisories               | CC BY 4.0                                                |
| [Ubuntu CVE tracker](https://ubuntu.com/security/cves)                      | Ubuntu status and fixes                      | Canonical's terms                                        |
| [Debian security tracker](https://security-tracker.debian.org/tracker)      | Debian status and fixes                      | Debian's terms                                           |
| [Alpine secdb](https://secdb.alpinelinux.org/)                              | Alpine fixed versions                        | Alpine's terms                                           |
| Trend Micro [download center feed][tm-feed] and [supported kernels][tm-ksp] | TMDS agent and Kernel Support Package lists  | Trend Micro's terms                                      |

[tm-feed]: https://s3.amazonaws.com/help-deepsecurity-trendmicro/Resources/CustomScripts/download-center/data/ds-dlc-feed-src/en-us/products_lts.json
[tm-ksp]: https://files.trendmicro.com/documentation/guides/deep_security/Kernel%20Support/20.0/Deep_Security_20_0_kernels_EN.html

CVE Desk normalizes and caches these documents; it does not redistribute them in bulk. Vendor names and logos are
trademarks of their owners and are used only to identify the vendor's data (see [docs/trademarks.md](docs/trademarks.md),
[logo attribution](assets/logos/README.md) and [fixture attribution](tests/fixtures/README.md)).

## TMDS Agent and Kernel Support Package matching

Deep Security Agent on Linux needs kernel-specific modules. CVE Desk tracks two official Trend Micro sources hourly:

- **Bundled agent kernels:** the latest LTS 20 agent package per supported OS and architecture is downloaded from the
  download center, its published SHA-256 checksum is verified, and the list of bundled `Plugin-VFS_Filter_<kernel>`
  descriptors is recorded. Archives are inspected in memory, never executed or extracted, and not kept.
- **Kernel Support Packages (KSP):** the supported-kernels page for Deep Security 20 is parsed per platform,
  architecture and kernel flavor, including partial support (Δ).

For each vendor kernel fix, a case shows whether a listed kernel of the same branch with an equal or newer build exists.
Limits: this compares names in Trend Micro's published lists; it is not a runtime certification and says nothing about
an installed agent. Distribution package versions and kernel release names use different schemes, so missing matches
stay **unverified**, not unsupported. The KSP "since" release is only known for kernels that appeared after this server
started watching. Details: [docs/tmds.md](docs/tmds.md).

## Development

Tooling: [uv](https://docs.astral.sh/uv/) for Python, [pnpm](https://pnpm.io/) for JavaScript tooling, Node.js for
tests and the build. Both package managers only resolve releases that are at least two days old.

```sh
uv sync                              # Python runtime and dev dependencies (.venv)
pnpm install                         # prettier, eslint, esbuild
uv run pre-commit install            # run all checks on every commit
git config blame.ignoreRevsFile .git-blame-ignore-revs

uv run pytest                        # backend tests
pnpm test                            # frontend tests (node --test)
pnpm run build                       # minified frontend bundle in dist/
uv run pre-commit run --all-files    # ruff, prettier, eslint and file checks
```

To run without Docker, start the server with `uv run python -m backend` (data goes to `data/`) and open
<http://localhost:8080>; the admin dashboard listens on <http://localhost:8081>. See [CONTRIBUTING.md](CONTRIBUTING.md)
for conventions and how to add a vendor source.

### Project layout

```text
backend/          FastAPI app, vendor providers, SQLite cache, TMDS inventory, backend tests
src/              Frontend ES modules (no framework)
index.html        App shell; style.css holds all styles (design tokens, dark mode)
assets/           Icon and vendor logos
legal/            Imprint/privacy page shell and German/English templates
tests/            Frontend tests (node --test) and reduced vendor fixtures
scripts/          Frontend build (esbuild)
docs/             Deployment, operations, evidence semantics, API, TMDS, trademarks
.github/          CI, image publishing, Dependabot, issue and PR templates
```

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, conventions, pull requests
- [SECURITY.md](SECURITY.md) — report vulnerabilities privately
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [docs/](docs/) — deployment, operations, evidence, API, TMDS, trademarks

Released under the [MIT License](LICENSE).
