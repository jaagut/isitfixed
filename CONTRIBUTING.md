# Contributing to CVE Desk

Thanks for your interest in improving CVE Desk. Bug reports, vendor-data corrections, documentation and code are all
welcome. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security problems privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

For larger changes or a new vendor source, please open an issue first so we can agree on the approach.

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), [pnpm](https://pnpm.io/) and Node.js (current LTS). Docker is optional
and only needed to build the image.

```sh
git clone https://github.com/jaagut/cve-viewer.git
cd cve-viewer
uv sync                                  # Python 3.13 runtime and dev dependencies in .venv
pnpm install                             # prettier, eslint, esbuild
uv run pre-commit install                # run the checks on every commit
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

Both package managers only resolve releases that have been public for at least two days (`exclude-newer` in
`pyproject.toml`, `minimumReleaseAge` in `pnpm-workspace.yaml`). Keep it that way when adding dependencies, and commit
the updated `uv.lock` or `pnpm-lock.yaml`.

Run the app with `docker compose up --build`, or without Docker with `uv run python -m backend` (public app on
port 8080, admin dashboard on 8081, data in `data/`).

## Checks

```sh
uv run pytest                            # backend tests (backend/test_*.py)
pnpm test                                # frontend tests (tests/*.test.js, node --test)
pnpm run build                           # production bundle (dist/)
uv run pre-commit run --all-files        # ruff, prettier, eslint, file hygiene
```

CI runs the same commands, builds the container image and scans it with Trivy. A pull request must pass all of them.

## Code style

- **Python:** formatted and linted with ruff (line length 120). Keep the backend small and dependency-light (FastAPI,
  httpx, the standard library).
- **JavaScript:** plain ES modules without a framework, formatted with prettier and linted with eslint. Use static
  `import` statements only; the build bundles them.
- **HTML and CSS:** no inline scripts, inline event handlers or `style="…"` attributes; the Content Security Policy
  blocks them. Colors are design tokens in `style.css` and must work in light and dark mode.
- **No third-party resources** at runtime: no CDNs, web fonts, analytics or remote images.
- **User-facing text** is short and plain. Never present missing data as "not affected".
- Formatting-only changes go in their own commit; add large reformatting commits to `.git-blame-ignore-revs`.

## Commits and pull requests

- Write commit subjects in the imperative mood, about 50–72 characters, without a trailing period (for example
  "Add Rocky Linux CSAF provider"). Explain the why in the body when it is not obvious.
- Keep pull requests focused on one change. Include tests for behavior changes and update the docs (`README.md`,
  `docs/`) when behavior, configuration or data handling changes.
- Changes to what data is stored, logged or sent must also update the privacy template in `legal/templates/` and the
  privacy summary in the README.
- Fill in the pull request template. Maintainers squash or rebase on merge.

## Adding a vendor source

Vendor sources live in [`backend/providers.py`](backend/providers.py); the frontend maps products and statuses in
[`src/data.js`](src/data.js) and [`src/feeds.js`](src/feeds.js).

1. **Pick an official, public, machine-readable source** (CSAF/VEX preferred) with a license or terms that allow
   automated access and display. Note the license in the README "Sources and licenses" table and add the vendor to
   [docs/trademarks.md](docs/trademarks.md).
2. **Fetch only fixed URLs** built from a validated CVE ID. Never fetch URLs taken from user input or from documents
   without validation. Set a time limit for the source and keep bulk documents only briefly in memory.
3. **Normalize conservatively.** Map vendor statuses to CVE Desk statuses without inferring more than the vendor says:
   absence is **No data**, upstream status does not imply distribution status, and unaffected ranges are not fixes.
   Report a vendor's "not published" answer separately from an outage.
4. **Sanitize errors.** Source failures must produce short user-facing messages, never raw exception text, and must keep
   previous evidence.
5. **Add the family** to the accepted vendor families, the OS/version lists in the frontend and, if the vendor has a
   logo, add the SVG under `assets/logos/` with its source and license in `assets/logos/README.md`.
6. **Add tests** with a reduced real excerpt under `tests/fixtures/` (keep only what the test needs, and add the source,
   fetch date and license to `tests/fixtures/README.md`), plus backend tests for parsing and failure handling.
7. **Document the semantics** of the new source in [docs/evidence.md](docs/evidence.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
