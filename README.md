# adyasoft_security — WordPress Security Scanner (Audit Mode)

Read-only, per-hosting-account WordPress compromise scanner. See
`docs/superpowers/specs/2026-08-17-wp-security-scanner-design.md` for the
full spec and architecture decisions.

## Deploying to a Hostinger hPanel account

1. Copy this entire directory to the account's home directory as a sibling
   of `public_html`, e.g. `~/security-scanner/`. No SSH or Composer needed
   on the host — only `src/`, `bin/`, `config/` are required at runtime.
2. In hPanel → Advanced → Cron Jobs, add two jobs:
   - Hourly: `php ~/security-scanner/bin/run.php --checks=cheap`
   - Daily: `php ~/security-scanner/bin/run.php --checks=expensive`
3. Reports and logs are written to `~/security-scanner/data/`, outside the
   web docroot.

## Pushing findings to the central dashboard

This scanner can optionally push each scan's findings to a central "findings
dashboard" — a separate project living under `dashboard/` in this repo and
deployed independently to its own hosting account. See `dashboard/README.md`
for its own deployment instructions and for how to issue an API key per
scanner deployment.

Every scanner deployment **must** have a `config/dashboard.php` file, even if
push is not being used yet: `bin/run.php` loads it unconditionally and will
fatal without it. This matters when updating an existing deployment in place by
copying new scanner files over an old one — make sure `config/dashboard.php`
comes along. It already exists in this repo as a working example (following the
same shape as `config/mail.php`) with a placeholder endpoint and API key. With
the placeholder values left in place the push simply fails and is logged as a
warning in `data/run.log` — it never blocks or fails the scan itself.

## Development

```
composer install
vendor/bin/phpunit
```
