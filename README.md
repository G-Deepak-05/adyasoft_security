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

## Development

```
composer install
vendor/bin/phpunit
```
