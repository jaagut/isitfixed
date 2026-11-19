# HTTP API

The frontend talks to the backend over a small JSON API. It has no user authentication; every response uses
`Cache-Control: no-store` so browser caching cannot hide server updates. When the operator sets `API_DOCS=true`, the
OpenAPI schema is served at `/openapi.json`. There is no interactive Swagger UI or ReDoc page, because those would load
third-party assets.

| Endpoint                                  | Purpose                                                   |
| ----------------------------------------- | --------------------------------------------------------- |
| `GET /api/health`                         | Health check for containers and uptime monitors           |
| `GET /api/config`                         | Server features for the frontend (see below)              |
| `GET /api/cves/{id}?families=…&refresh=…` | One case: CVE record and normalized vendor evidence       |
| `GET /api/cves/{id}/stream?families=…`    | Same, streamed as newline-delimited JSON while areas load |
| `PUT /api/workspaces/{uuid}/watches`      | Replace the watch set of one anonymous workspace          |
| `GET /api/tmds`                           | Trend Micro agent and Kernel Support Package inventory    |

## `GET /api/health`

- `200` with `"status": "ok"`: everything works.
- `200` with `"status": "degraded"`: the server works, but one or more upstream vendor sources are currently failing.
  This is not a reason to restart the container.
- `503` with `"status": "stalled"`: a background worker has not completed a loop iteration within its expected time
  and is stuck or dead. Container health checks that use a plain `GET` (as the image's `HEALTHCHECK` does) then mark
  the container unhealthy so it is restarted.

External uptime monitors should check for HTTP `200`.

## `GET /api/config`

```json
{
  "version": "1.1.0",
  "manualRefresh": false,
  "tmds": true,
  "legal": { "imprint": true, "privacy": true },
  "sourceUrl": "https://github.com/jaagut/isitfixed",
  "retentionDays": 10
}
```

## `GET /api/cves/{id}`

`families` is a comma-separated subset of `rhel`, `sles`, `debian`, `ubuntu` and `alpine`; an empty selection still
returns the CVE record. The response contains the CVE record, normalized `vendorData.evidence`, per-source URLs, fetch
timestamps and errors, and cache metadata (`watched`, `expiresAt`, `lastAttempt`, `retentionDays`, `refreshAfter`).
This endpoint alone does not register a watch.

- `refresh=true` forces an upstream refresh. It is rejected with `403` unless the server sets `MANUAL_REFRESH=true`.
- The response arrives within 180 seconds, including any wait for a refresh already in progress. On that deadline the
  server answers with what it has and marks the remaining sources with an error. Reverse proxies need a
  response-header timeout of at least 200 seconds for `/api/cves/*`; the `/stream` variant must not be buffered.
- `404`: the CVE Program has no such ID. `502`: the record and all vendor sources failed.
- `429`: rate limit or capacity reached; the response carries `Retry-After` (seconds).

## `PUT /api/workspaces/{uuid}/watches`

```json
{ "cases": [{ "id": "CVE-2026-98432", "families": ["rhel", "sles"] }] }
```

The request replaces that workspace's complete watch set; send `{"cases": []}` to stop all its watches. Each request
also marks the workspace as active. Limits:

- A workspace may watch up to `MAX_WATCHES_PER_WORKSPACE` CVEs (default 200); above that the server answers `422`.
- Server-wide caps answer `429`: at most `MAX_WATCHED_CVES` distinct watched CVEs (default 1000), `MAX_WORKSPACES`
  workspaces (default 5000) and `MAX_WATCH_ROWS` watch registrations in total (default 50000).
- Caps are checked against the watch set as it would be after the replacement, so a request that reduces a workspace's
  watches is always accepted.

The frontend keeps at most 200 open (non-archived) cases per browser; archived cases are not watched. The workspace
UUID is a bearer secret: anyone who knows it can replace that watch set, so keep it private.

## `GET /api/tmds`

Returns `{"enabled": false}` when the server sets `TMDS_ENABLED=false`. Otherwise it returns the bundled agent
inventory (`products`) and the Kernel Support Package inventory (`ksp`), each with `error`, `attempted`, `checked` and
`source`. See [tmds.md](tmds.md) for the meaning of the fields.
