# Findings Dashboard

Central multi-account view of security findings pushed from every
`adyasoft_security` scanner deployment. See
`docs/superpowers/specs/2026-08-17-findings-dashboard-design.md` for the
full design.

## Deploying to its own hPanel account

1. Copy this `dashboard/` directory to a hosting account's home directory,
   e.g. as `~/findings-dashboard/`, with `public/` set as that account's
   web root (or a subdirectory pointed at by a vhost). No SSH or Composer
   needed at runtime — only `src/`, `public/`, `config/` are required.
2. Create a MySQL database on that account and run `db/schema.sql` against
   it once (via hPanel's phpMyAdmin, or any MySQL client).
3. Copy `config/database.php.example` to `config/database.php` and fill in
   the real DSN/credentials for the database from step 2.
4. Create the first (and typically only) admin user:
   `php bin/create-user.php --username=<you> --password=<a strong password>`
5. Visit `/login.php` on the deployed URL.

## Connecting a scanner to this dashboard

On each scanner deployment (a separate hosting account running
`adyasoft_security`'s scanner):

1. Log into this dashboard, go to **Manage accounts**, create an account
   for that hosting account, and copy the API key shown (only shown once).
2. On the scanner's own account, edit `config/dashboard.php`: set
   `endpoint` to this dashboard's `https://.../ingest.php` URL and
   `api_key` to the key from step 1.
3. The scanner's next scan (via its existing cron jobs) will push its
   findings automatically. A push failure never blocks or fails the scan
   itself — it's logged to that scanner's own `data/run.log`.

## Development

```
cd dashboard
composer install
vendor/bin/phpunit
```
