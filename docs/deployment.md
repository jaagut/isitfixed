# Deployment

Is It Fixed ships as one container image (`ghcr.io/jaagut/isitfixed`, or built locally with `docker compose build`). One
process serves the public app on port 8080 and a private admin dashboard on port 8081; both share one event loop, the
hourly scheduler and the SQLite cache, so run exactly one replica per data volume.

- [Local use](#local-use)
- [Configuration reference](#configuration-reference)
- [Public hosting](#public-hosting)
- [Hardening responsibilities](#hardening-responsibilities)
- [Updates and rollback](#updates-and-rollback)
- [Migrating from the ./data bind mount](#migrating-from-the-data-bind-mount)

## Local use

```sh
docker compose up --build -d
```

The app is at http://localhost:8080 and the admin dashboard at http://localhost:8081; both ports bind to `127.0.0.1`
only. Compose runs the container with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, a
1.5 GiB memory limit, a PID limit, rotated `json-file` logs (2 × 5 MB) and a health check. Data lives in the named
volume `isitfixed-data` (`/data` in the container): the SQLite cache and, by default, the application log files.
`/tmp` is a disk-backed anonymous volume used to spool Trend Micro agent archives (up to ~350 MB while one is being
inspected).

Settings go into an optional `.env` file next to `compose.yaml` (not committed; it is read through `env_file`
with `required: false`). `compose.yaml` lists every variable as a commented example.

```sh
# .env
ADMIN_TOKEN=change-me-to-a-long-random-string
MANUAL_REFRESH=true
```

## Configuration reference

All settings are environment variables, read once at startup. Invalid values (for example `MANUAL_REFRESH=maybe`)
stop the process with a configuration error.

### Serving

| Variable              | Default                                             | Meaning                                                                                                                                                                                    |
| --------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `HOST`                | `127.0.0.1` (image: `0.0.0.0`)                      | Bind address of both servers.                                                                                                                                                              |
| `PORT`                | `8080`                                              | Public app port.                                                                                                                                                                           |
| `ADMIN_PORT`          | `8081`                                              | Admin dashboard port. Empty or `0` disables the dashboard.                                                                                                                                 |
| `ADMIN_TOKEN`         | unset                                               | When set, the dashboard requires `Authorization: Bearer <token>` or HTTP Basic auth with any user name and the token as password (compared in constant time). Still keep the port private. |
| `CACHE_DB`            | `data/cache.sqlite3` (image: `/data/cache.sqlite3`) | SQLite database path.                                                                                                                                                                      |
| `SERVE_FRONTEND`      | `true`                                              | Serve the frontend from the same origin. `false` serves only the API (and legal pages).                                                                                                    |
| `FRONTEND_DIR`        | repository root (image: `/app/dist`)                | Frontend files. The repository root serves the unbuilt sources (development); the image serves the minified, content-hashed build from `pnpm run build`.                                   |
| `CORS_ORIGINS`        | unset                                               | Comma-separated exact origins allowed to call the API cross-origin (separately hosted frontend).                                                                                           |
| `CSP_CONNECT_SRC`     | unset                                               | Extra `connect-src` origins in the Content-Security-Policy, when the frontend calls an API on another host.                                                                                |
| `HSTS`                | `false`                                             | Send `Strict-Transport-Security`. Normally set by the TLS reverse proxy instead.                                                                                                           |
| `API_DOCS`            | `false`                                             | Serve `/docs`, `/redoc` and `/openapi.json`. Swagger UI loads its bundle from jsDelivr, so the CSP is relaxed for those two pages only.                                                    |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1`                                         | Comma-separated proxy addresses whose `X-Forwarded-For`/`X-Forwarded-Proto` headers are trusted (uvicorn proxy headers). See [client addresses](#client-addresses-behind-a-proxy).         |
| `SITE_URL`            | unset                                               | Public URL of this instance (used in the legal pages).                                                                                                                                     |
| `SOURCE_URL`          | `https://github.com/jaagut/isitfixed`               | Source code link in the footer, `/api/config` and the User-Agent. Point it at your fork if you modify the code.                                                                            |
| `USER_AGENT`          | `isitfixed/<version> (+<SOURCE_URL>)`               | User-Agent for upstream requests.                                                                                                                                                          |

### Features

| Variable         | Default | Meaning                                                                                                                                                                          |
| ---------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MANUAL_REFRESH` | `false` | Show **Refresh data** and accept `refresh=true`. When `false`, `refresh=true` is rejected with HTTP 403; on-demand fetching of uncached CVEs is unaffected.                      |
| `TMDS_ENABLED`   | `true`  | Trend Micro Deep Security inventories (bundled agent descriptors and Kernel Support Packages). When `false`, no inventory jobs run and `/api/tmds` returns `{"enabled": false}`. |

### Capacity, retention and rate limits

| Variable                    | Default | Meaning                                                                                                                         |
| --------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `MAX_CACHED_CVES`           | `1000`  | Cached CVEs. When full, the least recently refreshed unwatched CVE is evicted.                                                  |
| `MAX_WATCHED_CVES`          | `1000`  | Distinct watched CVEs across all workspaces; a watch sync beyond it gets HTTP 429.                                              |
| `MAX_WATCHES_PER_WORKSPACE` | `200`   | Watched CVEs per workspace; a larger watch sync gets HTTP 422.                                                                  |
| `WORKSPACE_TTL_DAYS`        | `30`    | Workspaces whose browser has not synced for this long are removed with their watches (the ten-day cache retention then starts). |
| `RATE_LIMIT_REQUESTS`       | `240`   | All `/api` requests per client and minute (`/api/health` is exempt).                                                            |
| `RATE_LIMIT_LOOKUPS`        | `20`    | Lookups that contact upstream sources (uncached, due or newly selected vendors) per client and minute.                          |
| `RATE_LIMIT_LOOKUPS_GLOBAL` | `120`   | The same for all clients together, protecting the upstream vendors.                                                             |
| `RATE_LIMIT_WATCHES`        | `12`    | Watch-list syncs per client and minute.                                                                                         |

A value of `0` disables a rate limit. Rejected requests get HTTP 429 with `Retry-After` (seconds).

### Logging

| Variable             | Default                     | Meaning                                                                                                              |
| -------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `LOG_DIR`            | unset (image: `/data/logs`) | Write `isitfixed.log`, rotated at midnight UTC. Unset or empty: no log files.                                        |
| `LOG_LEVEL`          | `INFO`                      | Level for the log file (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Standard output only ever gets `WARNING`+. |
| `LOG_RETENTION_DAYS` | `14`                        | Days of log files kept (current file plus rotated ones), capped at 14. Older files are also deleted at startup.      |

Logs use UTC timestamps and contain no client addresses (IP-like strings are redacted as a safeguard), no workspace ids
and no access log. Upstream failures are logged at `WARNING` with technical detail; API responses only carry short
categories such as `DNS lookup failed` or `HTTP 503 from ubuntu.com`.

### Legal pages

| Variable                   | Meaning                                                                                                                          |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `LEGAL_OPERATOR_NAME`      | Operator name (required for the bundled templates).                                                                              |
| `LEGAL_OPERATOR_ADDRESS`   | Postal address (required). Use real newlines or a literal `\n`.                                                                  |
| `LEGAL_OPERATOR_EMAIL`     | Contact email (required).                                                                                                        |
| `LEGAL_OPERATOR_PHONE`     | Optional phone number.                                                                                                           |
| `LEGAL_RESPONSIBLE_PERSON` | Optional person responsible for content (§ 18 Abs. 2 MStV).                                                                      |
| `LEGAL_HOSTING_PROVIDER`   | Name and address of the hosting provider (privacy policy).                                                                       |
| `LEGAL_LAST_UPDATED`       | Date shown as "last updated" (defaults to the template date).                                                                    |
| `LEGAL_ACCESS_LOGS`        | `true` if your reverse proxy keeps access logs (with shortened IPs); adds that paragraph to the privacy policy. Default `false`. |
| `LEGAL_DIR`                | Directory with your own `imprint.html` / `privacy.html` body fragments, replacing the bundled ones.                              |

`/imprint` and `/privacy` (with redirects from `/impressum` and `/datenschutz`) are enabled when name, address and
email are set, or when `LEGAL_DIR` contains the page. Otherwise they return 404, `/api/config` reports them as
disabled, the footer hides their links and a warning is logged at startup. Fragments may use `{{placeholder}}` values
(HTML-escaped) and `<!-- if:name -->…<!-- endif:name -->` blocks that disappear when the value is empty; see
`legal/templates/`. The bundled texts are a starting point, not legal advice: review them for your jurisdiction.

### Other

| Variable           | Default | Meaning                                                                                                      |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------ |
| `WATCHDOG_TIMEOUT` | `120`   | Seconds the event loop may be unresponsive before the process exits so the container restarts. `0` disables. |

## Public hosting

A public instance needs a TLS-terminating reverse proxy in front of port 8080. [`deploy/Caddyfile.example`](../deploy/Caddyfile.example)
is a complete Caddy configuration:

- automatic HTTPS and HSTS;
- `flush_interval -1` for `/api/cves/*/stream`, so progressive results reach the browser line by line;
- a 256 KB request body limit;
- an access log with client addresses truncated to /24 (IPv4) and /48 (IPv6), kept for 14 days at most (or remove the
  `log` block to disable access logging);
- **no route to the admin port**.

Any other proxy works the same way. Requirements: forward `X-Forwarded-For` and `X-Forwarded-Proto`, do not buffer
`/api/cves/*/stream` responses (nginx: `proxy_buffering off`; the app also sends `X-Accel-Buffering: no`), allow
responses to take up to ~3 minutes (bulk vendor feeds) and keep the admin port private.

### Client addresses behind a proxy

Rate limits are per client address. Uvicorn takes the address from `X-Forwarded-For` only when the connection comes
from an address in `FORWARDED_ALLOW_IPS`. With the default (`127.0.0.1`) and a proxy on the Docker host, the
container sees the Docker bridge gateway (for example `172.17.0.1`) instead, so **all visitors would share one rate
limit**. Set `FORWARDED_ALLOW_IPS` to the address the proxy connects from (the bridge gateway, or the proxy
container's address on a shared network). `*` trusts every peer and is only acceptable when nothing but the proxy can
reach port 8080. The CSP adds `upgrade-insecure-requests` only for requests that arrived over HTTPS, which also relies on
a trusted `X-Forwarded-Proto`.

### Security headers

Every response carries a strict Content-Security-Policy (`default-src 'self'`, no inline scripts or styles,
`frame-ancestors 'none'`, `upgrade-insecure-requests` on HTTPS), `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, a `Permissions-Policy` denying camera, microphone, geolocation, payment, USB and
interest-cohort/topics, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin` and
`X-Frame-Options: DENY`. Hashed bundle files are cached for a year (`immutable`), logos for a day and pages are
revalidated (`no-cache`); API responses use `no-store`.

### Container contract

- Runs as uid:gid `10001:10001`; works with a read-only root filesystem. Writable paths: `/data` (volume) and `/tmp`
  (~400 MB free recommended).
- Ports 8080 (public) and 8081 (admin), bound to `0.0.0.0` inside the container.
- Health check: `GET /api/health` returns HTTP 200 with `{"status": "ok" | "degraded", "workers": {…}}` while the
  process serves requests. `degraded` means a background worker has not reported progress for a while; upstream
  outages alone never fail the health check.
- `SIGTERM` stops both servers gracefully (within ~20 s).

## Hardening responsibilities

| Layer         | Responsibility                                                                                                                                                                                                                                                                                                  |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| App           | Input validation, fixed upstream URLs, per-download size caps and deadlines, per-source backoff, rate limits, watch/cache caps, workspace expiry, security headers, sanitized errors, minimal logs, private admin port with optional token, watchdog restart.                                                   |
| Container     | Non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory/CPU/PID limits, log rotation, health check, restart policy (see `compose.yaml`).                                                                                                                                         |
| Reverse proxy | TLS and HSTS, request body limit, unbuffered stream route, access-log minimisation (masked addresses, ≤ 14 days or off), no route to the admin port, optional extra request limits.                                                                                                                             |
| Host          | Firewall allowing only 80/443 (and SSH/VPN); SSH with keys only, no password or root login; unattended security upgrades; time synchronisation (NTP); the admin port reachable only through a VPN such as WireGuard or an SSH tunnel; `journald` retention capped (`MaxRetentionSec=14day`); disk monitoring.   |
| Operations    | An external uptime monitor on `https://<site>/api/health`; image updates (below); optional backups of the `isitfixed-data` volume (the cache can be rebuilt, so backups mainly preserve watch registrations); a data processing agreement (AVV/DPA) with the hosting provider; keeping the legal pages current. |

## Updates and rollback

Pin the image by version tag (`ghcr.io/jaagut/isitfixed:1.1.0`) or digest in production, and update deliberately:

```sh
docker pull ghcr.io/jaagut/isitfixed:1.2.0
# change the tag in your deployment, then
docker compose up -d
```

To roll back, start the previous tag again. Database schema upgrades are applied automatically at startup and are
forward-only (`PRAGMA user_version`); an older release keeps working on a newer schema only when the release notes say
so. Back up the volume before upgrading across a schema change if the watch registrations matter to you (the cache
itself refills from the vendors). For a local checkout, `git pull && docker compose up --build -d` rebuilds the image.

## Upgrading an existing CVE Desk deployment

The rebrand changes the Compose volume name from `cve-desk-data` to `isitfixed-data`. Before upgrading, stop the old
container and copy its volume into the new one (never copy a live SQLite database):

```sh
docker compose down
docker volume create isitfixed-data
docker run --rm -v cve-desk-data:/from:ro -v isitfixed-data:/to alpine \
  sh -c 'cp -a /from/. /to/ && chown -R 10001:10001 /to'
docker compose up --build -d
```

Keep the old volume until you have verified the upgrade. Browser workspaces now use IndexedDB and start fresh;
legacy localStorage is not migrated. Browser storage remains origin-specific.
New application logs use `isitfixed.log`; the retention task also removes expired pre-rebrand logs.

## Migrating from the ./data bind mount

Earlier versions mounted `./data` into the container as root. The image now runs as uid 10001 and Compose uses the
named volume `isitfixed-data`. Copy the old data once, fixing ownership:

```sh
docker compose down
docker volume create isitfixed-data
docker run --rm -v "$PWD/data:/from:ro" -v isitfixed-data:/to alpine \
  sh -c 'cp -a /from/. /to/ && chown -R 10001:10001 /to'
docker compose up --build -d
```

After verifying the app (your watched cases are listed on the admin dashboard as watched CVEs), the old `./data`
directory can be deleted. Existing databases are upgraded in place on first start; existing watches start their
30-day workspace inactivity clock at the upgrade.
