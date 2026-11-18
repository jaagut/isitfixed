## Summary

<!-- What does this change and why? Link related issues, e.g. "Fixes #123". -->

## How was this tested?

<!-- Commands you ran, CVEs you checked in the app, screenshots for UI changes (light and dark mode). -->

## Checklist

- [ ] `uv run pre-commit run --all-files` passes
- [ ] Tests added or updated; `uv run pytest` and `pnpm test` pass
- [ ] Docs updated (`README.md`, `docs/`) if behavior or configuration changed
- [ ] Privacy template (`legal/templates/privacy.html`) and README privacy summary updated if this changes what is
      stored, logged or sent
- [ ] No new third-party runtime resources (CDNs, fonts, analytics), inline scripts or inline styles
- [ ] Missing vendor data is still shown as **No data**, never as "not affected"
