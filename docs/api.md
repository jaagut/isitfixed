# HTTP API

The frontend talks to the backend over a small JSON API. It has no user authentication; every response uses
`Cache-Control: no-store` so browser caching cannot hide server updates. Interactive API docs are available at `/docs`
only when the operator sets `API_DOCS=true`; that page loads Swagger UI from a CDN, so keep it disabled on public
instances.

| Endpoint                                  | Purpose                                                   |
| ----------------------------------------- | --------------------------------------------------------- |
| `GET /api/health`                         | Liveness check used by the container healthcheck          |
| `GET /api/config`                         | Server features for the frontend (see below)              |
| `GET /api/cves/{id}?families=…&refresh=…` | One case: CVE record and normalized vendor evidence       |
| `GET /api/cves/{id}/stream?families=…`    | Same, streamed as newline-delimited JSON while areas load |
| `PUT /api/workspaces/{uuid}/watches`      | Replace the watch set of one anonymous workspace          |
| `GET /api/tmds`                           | Trend Micro agent and Kernel Support Package inventory    |

## `GET /api/config`

```json
{
  "version": "1.1.0",
  "manualRefresh": false,
  "tmds": true,
  "legal": { "imprint": true, "privacy": true },
  "sourceUrl": "https://github.com/jaagut/cve-viewer",
  "retentionDays": 10
}
```

## `GET /api/cves/{id}`

`families` is a comma-separated subset of `rhel`, `sles`, `debian`, `ubuntu` and `alpine`; an empty selection still
returns the CVE record. The response contains the CVE record, normalized `vendorData.evidence`, per-source URLs, fetch
timestamps and errors, and cache metadata (`watched`, `expiresAt`, `lastAttempt`, `retentionDays`, `refreshAfter`).
This endpoint alone does not register a watch.

- `refresh=true` forces an upstream refresh. It is rejected with `403` unless the server sets `MANUAL_REFRESH=true`.
- `404`: the CVE Program has no such ID. `502`: the record and all vendor sources failed.
- `429`: rate limit or capacity reached; the response carries `Retry-After` (seconds).

## `PUT /api/workspaces/{uuid}/watches`

```json
{ "cases": [{ "id": "CVE-2026-98432", "families": ["rhel", "sles"] }] }
```

The request replaces that workspace's complete watch set; send `{"cases": []}` to stop all its watches. Each request
also marks the workspace as active. A workspace may watch up to `MAX_WATCHES_PER_WORKSPACE` CVEs (`422` above that); the
server watches at most `MAX_WATCHED_CVES` CVEs in total (`429` above that). The workspace UUID is a bearer secret:
anyone who knows it can replace that watch set, so keep it private.

## `GET /api/tmds`

Returns `{"enabled": false}` when the server sets `TMDS_ENABLED=false`. Otherwise it returns the bundled agent
inventory (`products`) and the Kernel Support Package inventory (`ksp`), each with `error`, `attempted`, `checked` and
`source`. See [tmds.md](tmds.md) for the meaning of the fields.
