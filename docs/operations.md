# Operations

Day-to-day running of an Is It Fixed instance. Configuration is described in [deployment.md](deployment.md).

## Admin dashboard

The dashboard is a second server in the same process on `ADMIN_PORT`. It is off by default; set `ADMIN_PORT` (for
example `8081`) to enable it. It is meant for the operator only: never route it through the public reverse proxy; reach it through a VPN (for example Tailscale) or an SSH tunnel:

```sh
ssh -L 8081:127.0.0.1:8081 your-server   # then open http://localhost:8081
```

Set `ADMIN_TOKEN` to require `Authorization: Bearer <token>` (or HTTP Basic auth with any user name and the token as
password) as a second line of defence. The page is plain server-rendered HTML without JavaScript and reloads every 30
seconds; `GET /api/stats` returns the same numbers as JSON for scripts or monitoring.

It shows:

- version, uptime and feature flags (manual refresh, TMDS, API docs, HSTS, token, log files, legal pages) and the
  configured limits;
- cached CVEs, watched CVEs and workspaces (counts only);
- refreshes in the last ~1 hour, ~24 hours and 14 days, split into scheduled (background), on-demand (lookups) and
  manual (**Refresh data**);
- upstream fetches and failures per source (`record`, `rhel`, `sles`, `ubuntu`, `debian`, `alpine`, `tmds-agents`,
  `tmds-ksp`) with the last sanitized error, its time and the current backoff;
- HTTP 429 responses per rate-limit budget;
- Trend Micro inventory status (last success and attempt, error, number of agent releases, KSP platforms and kernels);
- process memory (RSS) and CPU, container memory usage and limit (cgroup v2), database size, free space on the data
  volume and the size of the log directory;
- heartbeat age of each background worker.

Counters are kept in hourly buckets (in memory, persisted to SQLite every minute) for 14 days. They contain no IP
addresses, no workspace ids and no link between CVEs and workspaces. The time windows are approximate: "1 h" covers the
current and the previous full hour bucket.

## Health and restarts

`GET /api/health` returns HTTP 200 with status `ok` or `degraded` for upstream outages, and HTTP 503
with status `stalled` when a background worker is stuck or dead. Point an external uptime monitor at
it expecting HTTP 200. The `workers` object includes each worker's heartbeat age; source errors and
backoff are also visible on the dashboard.

A watchdog thread exits the process (status 1, logged as `CRITICAL`) when the event loop has been unresponsive for
`WATCHDOG_TIMEOUT` seconds (default 120); the restart policy (`restart: unless-stopped`) then starts a fresh container.

## Upstream failures and backoff

Every download has a size cap and an overall deadline (30 s for per-CVE documents, 150 s for bulk feeds, 2 minutes for
the Trend Micro feed and kernel page, 10 minutes per agent archive) in addition to per-operation network timeouts, so
a stalled upstream cannot hold a request or worker indefinitely.

After three consecutive failures of a CVE source the source is paused for 1 minute, then 2, 4, 8 … up to 30 minutes
for each further failure; the first success resets it. The Trend Micro inventories back off from their first failure
and retry on that schedule instead of waiting for the next hourly run. While paused, no request is sent upstream,
previously fetched evidence is kept, and the source shows "temporarily paused after repeated failures; next attempt
after HH:MM UTC" with a `retryAfter` timestamp. A vendor answering 404 ("not published") is not a failure. Backoff
state is held in memory and resets on restart.

## Logs

- Standard output (`docker compose logs`) only carries warnings and errors.
- With `LOG_DIR` (default `/data/logs` in the image), `isitfixed.log` gets messages at `LOG_LEVEL` (default `INFO`),
  rotates at midnight UTC and keeps at most `LOG_RETENTION_DAYS` days (≤ 14). Older files are deleted at startup too.
- There is no access log in the app. Client addresses, workspace ids and tokens are never logged; IP-like strings in
  messages are redacted.
- Docker's `json-file` driver is limited to 2 × 5 MB in `compose.yaml`. On hosts with journald, cap its retention
  (`MaxRetentionSec=14day`). Proxy access logs need their own limit (see `deploy/Caddyfile.example`).

## Rate-limit tuning

Budgets are token buckets per client and minute (bursts up to the per-minute value), configured with
`RATE_LIMIT_REQUESTS` (all API calls, default 240), `RATE_LIMIT_LOOKUPS` (lookups that contact upstream, default 20),
`RATE_LIMIT_LOOKUPS_GLOBAL` (the same across all clients, default 120) and `RATE_LIMIT_WATCHES` (watch syncs,
default 12). Lookups answered from the cache do not use the lookup budgets.

- Many 429s for `requests` from normal use usually mean that all visitors share one address: check
  `FORWARDED_ALLOW_IPS` ([deployment.md](deployment.md#client-addresses-behind-a-proxy)). Organisations behind one NAT
  address may also need higher values.
- `lookups-global` rejections protect the vendors; raise the value only moderately.
- `0` disables a budget (for example on a private single-user instance).

Clients are identified by HMAC-SHA256 of their address with a random key that exists only in memory and is replaced
every 24 hours; buckets reset with it. Nothing about clients is written to disk or logs. At most 20,000 buckets are
kept; the least recently used ones are dropped first.

## Data retention

| Data                                  | Retention                                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Cached CVE data                       | While watched; removed 10 days after the last workspace stops watching (or was never watched).         |
| Workspaces and their watches          | Removed after 30 days without a watch sync (`WORKSPACE_TTL_DAYS`); open browsers sync every 5 minutes. |
| Trend Micro inventories               | Entries not seen upstream for 10 days are removed.                                                     |
| Bulk vendor feeds (Debian, Alpine)    | In memory for at most one hour.                                                                        |
| Usage counters                        | Hourly buckets, 14 days.                                                                               |
| Application logs                      | ≤ 14 days (`LOG_RETENTION_DAYS`).                                                                      |
| Rate-limit state                      | In memory only; keyed hashes with a daily key rotation; lost on restart.                               |
| Browser data (cases, notes, settings) | Only in the visitor's browser (IndexedDB) until they delete it.                                        |

SQLite runs with `secure_delete` and without a persistent write-ahead log, so deleted rows do not linger in the
database file.
