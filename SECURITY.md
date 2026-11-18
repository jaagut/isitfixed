# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/jaagut/cve-viewer/security/advisories/new) (repository **Security** tab →
**Advisories** → **Report a vulnerability**). Include the affected version or commit, steps to reproduce, and the
impact you expect.

What to expect:

- An acknowledgement within 7 days.
- An assessment and, if confirmed, a fix or mitigation plan within 30 days, depending on severity and complexity.
- Credit in the advisory and release notes if you want it.
- Coordinated disclosure: please give us a reasonable time to release a fix before publishing details.

This is a volunteer-maintained project; there is no bug bounty.

## Supported versions

| Version                            | Supported |
| ---------------------------------- | --------- |
| Latest release (`latest`, `X.Y.Z`) | Yes       |
| `main` branch and `main` image     | Yes       |
| Older releases                     | No        |

Fixes are released as a new version. Operators should update to the latest image; base-image updates are published
regularly.

## Scope

In scope:

- The CVE Desk backend, frontend, container image and the default configuration in this repository.
- Vulnerabilities such as injection, cross-site scripting, server-side request forgery, path traversal, denial of
  service through unbounded resource use, leaks of workspace IDs or other data between users, and bypasses of rate
  limits or capacity caps.

Out of scope:

- Incorrect, incomplete or delayed vendor data. Please open a normal issue, or report it to the vendor.
- Vulnerabilities in third-party vendor sites or feeds.
- Misconfiguration of a specific deployment (reverse proxy, TLS, firewall, admin port exposure) that is not caused by
  insecure defaults or documentation in this repository. Report those to the operator of that instance.
- Reports from automated scanners without a demonstrated impact, missing best-practice headers without an exploit, and
  social engineering.

## How CVE Desk protects users

- **No accounts and minimal data.** Cases stay in the browser. The server stores only CVE IDs and vendor families per
  anonymous, random workspace ID, plus cached public vendor data. Inactive workspaces expire.
- **No tracking.** No cookies, analytics or third-party resources. Fonts and logos are served locally.
- **No stored IP addresses.** Application logs contain no IP addresses or workspace IDs and are kept for at most 14 days.
  Rate limiting uses an HMAC of the client IP with an in-memory key that rotates daily and is never persisted.
- **Fixed upstream URLs.** The server only fetches official vendor URLs built from validated CVE IDs, never URLs
  supplied by users. Request inputs are validated strictly (CVE ID format, vendor family allow-list, size limits).
- **Bounded resources.** Per-client rate limits, per-workspace and global watch caps, a bounded cache, per-source time
  limits and download size limits. Trend Micro agent archives are verified against the published SHA-256 checksum,
  inspected in memory and never executed or extracted.
- **Restrictive browser policy.** A strict Content Security Policy without inline scripts or styles, `no-store` API
  responses, and only explicitly listed frontend files are served; the database and source tree are never exposed.
- **Hardened container.** Runs as an unprivileged user (uid 10001), works with a read-only root filesystem, and writes
  only to `/data` and `/tmp`. The admin dashboard listens on a separate port intended for VPN-only access.
- **Supply chain.** Locked dependencies that must be at least two days old, GitHub Actions pinned to commit SHAs,
  Dependabot updates, image scans with Trivy in CI and weekly, and container images with SBOM and provenance
  attestations.
