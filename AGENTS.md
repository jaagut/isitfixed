# Is It Fixed

Is It Fixed is a small, self-hostable workspace for tracking individual CVEs across Linux distributions and Windows. A
FastAPI server fetches, normalizes and caches public vendor data (Red Hat, SUSE, Ubuntu, Debian, Alpine, the CVE record
and Trend Micro's Deep Security lists). A framework-free browser app keeps the user's cases in IndexedDB and shows
per-version vendor status, fixes and advisories.

## What makes Is It Fixed special?

Similar vulnerability tracking apps exist, but none let users curate their own list of watched cases and get notified
easily when they change, with refreshes every hour.

### 1. Honest about evidence

Missing evidence is **No data**, never "not affected". We normalize conservatively and never infer more than the
vendor says. Notifications fire only for changes worth acting on, not for timestamps.

### 2. Private by design

No accounts, cookies, analytics or third-party resources. Cases live in the browser; the server knows only CVE IDs
and vendor families per anonymous workspace ID. Keep it that way.

### 3. Open

We share our code and how we think about things, and we work in the open.

## A note from Jan

I like ambitious ideas, simple systems, and software that feels obvious. Do not preserve complexity just because it
already exists. Do not introduce machinery because it looks architecturally impressive. Understand the real constraint,
then fight for the smallest model that makes the correct behavior unsurprising.

Channel both "measure twice, cut once" and "yagni". Fight scope creep. Try to honor the dev's intent in both a minimal
and realistic fashion.

The rest of this document is meant to help you navigate the codebase and make changes effectively. Think of these
instructions less as "hard rules", more as "good defaults". The developer's preferences should be able to override
anything here.

## A small glossary

We need to be on the same page with terminology. When communicating, use this language:

- **you** means the agent reading this file and changing Is It Fixed.
- **we, us, and maintainers** mean people building Is It Fixed. These are who you are talking to now.
- **user** means the person using Is It Fixed to track vulnerabilities.
- **operator** means whoever hosts an instance.
- **case** is one CVE a user tracks in their browser, with the OS versions they selected.
- **vendor** (or **source**) is an upstream publisher of evidence, such as Red Hat CSAF or the Debian tracker. A
  **family** is the vendor key a request selects (`rhel`, `sles`, `debian`, `ubuntu`, `alpine`).
- **provider** is the backend code that fetches and normalizes one source.
- **workspace** is a browser's anonymous random ID; a **watch** is a CVE plus families registered under it, which the
  server refreshes on a schedule.
- **TMDS** is Trend Micro Deep Security; **KSP** is its Kernel Support Package list.

## Verifying

Before you push, run the same checks as CI:

```sh
uv run pre-commit run --all-files   # ruff, prettier, eslint, file hygiene
uv run pytest                       # backend tests (backend/test_*.py)
pnpm test                           # frontend tests (tests/*.test.js, node --test)
pnpm run build                      # production bundle (dist/)
```

CI also builds the container image and scans it with Trivy. Run the app with `uv run python -m backend` (port 8080,
data in `data/`) or `docker compose up --build` when you need to see a change working.

## Pull requests

- Never make a PR unless the developer explicitly asks you to do so.
- Commit and PR titles: imperative mood, plain language, 50–72 characters, no trailing period, no conventional-commit
  prefix: `Accept unassessed SUSE CSAF documents`.
- Fill in [the PR template](.github/pull_request_template.md). Summary: the problem in a sentence or two, then how
  you fixed it. End with the model and harness that did the work.
- UI changes need before- and after-screenshots in light and dark mode.
- Upload PR evidence to GitHub. Never commit PR-only screenshots or assets such as `.github/pr-assets/`.
- One request is one PR. Split it only when the maintainer asks.
- When babysitting: call `watch_pull_request` and end your turn. Do not poll or sleep. Verify each bot finding against
  the source, fix real ones, dismiss false positives with a written reason. Stay quiet when nothing is new. Stop when
  checks are green on the latest commit.

## Documentation

Most code changes do not need a documentation change. Agents can read the code.

- `README.md` is the user and operator overview: features, quick start, main configuration, privacy summary, sources.
  Update it when one of those changes.
- `docs/` holds the references for deployment, operations, evidence semantics, the API and TMDS. Update the page
  whose behavior changed; rewrite or remove outdated text instead of appending another account.
- Changes to what is stored, logged or sent must update the privacy template in `legal/` and the README privacy summary.
- A new vendor source follows [Adding a vendor source](CONTRIBUTING.md#adding-a-vendor-source), including its docs
  steps.
- Do not document every feature, enumerate fields, narrate control flow or append PR summaries. A local reason the
  code can't show goes in a short nearby code comment.

## Plans and work artifacts

- Do not commit implementation plans, research notes, or agent scratch files. Keep temporary working material outside
  the worktree.
- Track active work in the GitHub issue that owns it. A merged PR is the implementation record.

## How it works

Is It Fixed uses a pull model. The browser stores cases and an anonymous workspace ID in IndexedDB and asks the server
for a CVE and the selected families. The server fetches the CVE record and vendor documents on demand through the
providers, normalizes them and caches the result in SQLite. Saved cases are registered as watches; a background worker
refreshes all watched CVEs on a schedule, also while no browser is open. The open browser re-checks its cases and marks
those with changes worth acting on as **New**. Unwatched cache data and idle workspaces expire.

Semantics and caching: [docs/evidence.md](docs/evidence.md). API: [docs/api.md](docs/api.md).

## Where code lives

- `backend/` - FastAPI app, vendor providers, SQLite cache, background jobs, TMDS/KSP inventory, the private admin
  dashboard, and the backend tests with their fixtures.
- `src/` - frontend ES modules, no framework. `index.html` is the app shell, `style.css` holds all styles and design
  tokens.
- `tests/` - frontend tests and reduced real vendor fixtures.
- `legal/` - imprint and privacy pages. `deploy/` - example reverse proxy config. `scripts/` - frontend build.

## Taste

- Keep the backend small and dependency-light: FastAPI, httpx and the standard library. Do not add a dependency for
  what a few lines can do.
- Normalize conservatively. Absence is **No data**, upstream status does not imply distribution status, unaffected
  ranges are not fixes, and a vendor's "not published" is not an outage.
- Fetch only fixed official URLs built from a validated CVE ID. Every source has a time limit and a size limit.
- Source failures produce short user-facing messages, never raw exception text, and keep previous evidence.
- Plain ES modules with static `import`s only; the build bundles them. No inline scripts, inline event handlers or
  `style="…"` attributes; the Content Security Policy blocks them.
- Colors are design tokens and must work in light and dark mode. No CDNs, web fonts, analytics or
  remote images.
- User-facing text is short and plain.
- Behavior changes come with tests. Vendor parsing tests use reduced real excerpts, not invented documents.
- Respect the minimum release age for dependencies (`exclude-newer`, `minimumReleaseAge`). Commit the updated lockfile.
- Default to no comment. Write one only for a constraint, an external quirk, or an invariant the code can't show.
- If a rule here fights the task in front of you, say so loudly and get a human sign-off before breaking it.

## Additional tips

- Security matters here: this is a public, unauthenticated service that fetches from the internet. Still, do not
  over-index on it for maintainer-only features such as the admin dashboard.
- Before a security audit or triaging a vulnerability report, read [SECURITY.md](SECURITY.md) for the trust model and
  what is in scope.
