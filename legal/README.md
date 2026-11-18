# Imprint and privacy pages

CVE Desk can serve an imprint (`/imprint`, alias `/impressum`) and a privacy policy (`/privacy`, alias `/datenschutz`)
for operators in Germany. The pages are rendered by the backend from:

- `page.html` — the page shell (layout, stylesheet, footer), and
- `templates/imprint.html` and `templates/privacy.html` — the page content as HTML fragments, German first
  (authoritative), followed by an English translation.

> **The templates are not legal advice.** They describe the unmodified application as shipped in this repository, run
> by a private, non-commercial operator in Germany. Review them before publishing and adapt them to your setup, in
> particular your reverse proxy and its access logs, your hosting provider, backups, and any code changes. If in doubt,
> ask a lawyer.

## Enabling the pages

The pages are enabled when `LEGAL_OPERATOR_NAME`, `LEGAL_OPERATOR_ADDRESS` and `LEGAL_OPERATOR_EMAIL` are set, or when
`LEGAL_DIR` provides the file. Otherwise they return 404, the footer links are hidden (`/api/config` reports
`"legal": {"imprint": false, "privacy": false}`) and a warning is logged at startup.

| Variable                   | Placeholder                | Notes                                                                                                                                |
| -------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `LEGAL_OPERATOR_NAME`      | `{{operator_name}}`        | Required. Full name (or organisation and authorised representative)                                                                  |
| `LEGAL_OPERATOR_ADDRESS`   | `{{operator_address}}`     | Required. Postal address; separate lines with real newlines or `\n`                                                                  |
| `LEGAL_OPERATOR_EMAIL`     | `{{operator_email}}`       | Required. Contact e-mail address                                                                                                     |
| `LEGAL_OPERATOR_PHONE`     | `{{operator_phone}}`       | Optional. The phone line is omitted when empty                                                                                       |
| `LEGAL_RESPONSIBLE_PERSON` | `{{responsible_person}}`   | Optional. Person responsible for content under § 18 Abs. 2 MStV and address                                                          |
| `LEGAL_HOSTING_PROVIDER`   | `{{hosting_provider}}`     | Optional. Name and address of the hosting provider (processor, Art. 28 GDPR); the section is omitted when empty                      |
| `SITE_URL`                 | `{{site_url}}`             | Optional. Public URL of the instance                                                                                                 |
| `SOURCE_URL`               | `{{source_url}}`           | Source code link; defaults to this repository                                                                                        |
| `LOG_RETENTION_DAYS`       | `{{log_retention_days}}`   | Default and maximum 14                                                                                                               |
| `WORKSPACE_TTL_DAYS`       | `{{workspace_ttl_days}}`   | Default 30                                                                                                                           |
| –                          | `{{cache_retention_days}}` | Fixed: 10 days after the last workspace stops watching a CVE                                                                         |
| `LEGAL_LAST_UPDATED`       | `{{last_updated}}`         | Defaults to the date of the bundled templates                                                                                        |
| `LEGAL_ACCESS_LOGS`        | `{{access_logs}}` (block)  | `true` when the reverse proxy keeps access logs with shortened IPs; enables that privacy paragraph. Default `false` (no access logs) |
| `LEGAL_DIR`                | –                          | Directory with your own `imprint.html` and/or `privacy.html`                                                                         |

Example (Compose):

```yaml
environment:
  SITE_URL: https://cve.example.org
  LEGAL_OPERATOR_NAME: Erika Mustermann
  LEGAL_OPERATOR_ADDRESS: "Musterstraße 1\n12345 Musterstadt\nDeutschland"
  LEGAL_OPERATOR_EMAIL: cve-desk@example.org
  LEGAL_HOSTING_PROVIDER: 'Example Hosting GmbH, Beispielweg 2, 54321 Beispielstadt, Deutschland'
```

## Using your own texts

Set `LEGAL_DIR` to a directory mounted into the container (read-only is fine) that contains `imprint.html` and/or
`privacy.html`. A file found there replaces the bundled template for that page, even when the `LEGAL_OPERATOR_*`
variables are not set. The easiest start is to copy the bundled templates and edit them.

Your fragments use the same syntax:

- `{{name}}` inserts a value. Values are HTML-escaped; newlines become `<br>`.
- `<!-- if:name -->…<!-- endif:name -->` keeps the enclosed block only when `name` has a value.
- Content is static HTML (`h2`, `h3`, `p`, `ul`, `address`, `a`, …). Scripts, inline styles and external resources
  are not allowed: the Content Security Policy blocks them, and the privacy policy promises there are none.

## What to check before publishing

- **Imprint:** a private, non-commercial site may not strictly need a full imprint under § 5 DDG, but § 18 Abs. 1 MStV
  still asks for name and address for most public sites, so the template always includes them. Add the responsible
  person (§ 18 Abs. 2 MStV) only if you publish journalistic-editorial content. The consumer dispute resolution
  paragraph is commented out; it is only relevant for traders.
- **Privacy policy:** confirm that your reverse proxy does not log full IP addresses (or adapt the "logs" section),
  that its logs are deleted within `LOG_RETENTION_DAYS`, and that you have a data processing agreement with your hosting
  provider. Mention backups if they contain the database. If you change what the application stores, logs or sends,
  update the policy.
- Set `LEGAL_LAST_UPDATED` when you change the texts.
