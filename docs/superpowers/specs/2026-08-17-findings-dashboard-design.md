# Multi-Account Findings Dashboard — Design

**Status:** Draft, approved section-by-section in chat with the user
**Owner:** Security / Engineering
**Depends on:** `docs/superpowers/specs/2026-08-17-wp-security-scanner-design.md` (the scanner this dashboard aggregates data from)

---

## 1. Summary

A small centralized web application that lets one person view security findings from *every* WordPress hosting account running the scanner (see the scanner's own spec) in one place — a single, filterable, all-findings table instead of checking each account's local report/email separately. This directly implements what the scanner's spec named as out-of-scope P2 work (FR-33: "a simple aggregated dashboard/view across all sites' current risk status") plus the centralized-delivery half of FR-30 that the scanner's own plan deferred.

---

## 2. Problem Statement

The scanner (already built) runs independently per hosting account, by design — each account's cron job scans its own sites and emails/digests its own findings. That isolation is correct and load-bearing (NFR-4), but it means there is no single place to see "everything currently flagged across every account I manage." Today that requires opening each account's email/report individually.

---

## 3. Goals

1. One filterable view of every finding, across every hosting account that's been registered, without needing to log into or read reports from each account separately.
2. Filter by severity, hosting account/site, finding type, and date range.
3. Each account's scanner pushes its findings after every scan; the dashboard never reaches back into any scanned site — it only has what was pushed to it.
4. Single-admin login gate, since this aggregates sensitive data (compromise indicators, usernames, file paths) across multiple clients' sites into one place.

## 3.1 Non-Goals (out of scope for this design)

- Any write/remediation action from the dashboard against a scanned site (that's explicitly out of scope for the scanner itself too — see its spec's NFR-1).
- Multi-user roles/permissions — single admin login only.
- Real-time push notifications from the dashboard (email alerting already exists per-account via the scanner's `Mailer`; this dashboard is a read view, not a second alerting channel).
- Editing/annotating findings (e.g. "mark reviewed") — noted as a possible v2, not built now.
- Historical trend analysis / charts — the FR-33 language mentions this as a stretch goal; this design is the minimum "see everything" view, not analytics.

---

## 4. Architecture

Two independently-deployable components, both versioned in this repo:

```
adyasoft_security/
  src/, bin/, config/, tests/     ← existing scanner (unchanged except one addition)
  dashboard/                       ← new: the central app
    public/
      ingest.php                  ← API-key-authenticated push endpoint
      index.php                   ← login-gated findings view
      login.php
      accounts.php                ← manage hosting accounts / API keys
    src/                           ← dashboard's own PHP classes (PSR-4, same autoload style)
    config/
    tests/
```

Data flows one direction only: **scanner → push → central MySQL → dashboard reads.** The dashboard has no path back to any scanned site — it never receives site credentials or filesystem access, only the findings a scanner chose to send it via `FindingsPusher`. This preserves the scanner's own per-site isolation guarantee (NFR-4): a compromised site's scan can produce bad *findings data*, but the dashboard has no channel through which that could become a write against any site.

The two components are deployed separately: the scanner stays on each hosting account exactly as documented in its own README; `dashboard/` gets copied to its own separate hPanel account, matching the existing scanner's "copy files, no build step, no SSH needed" deployment model (see scanner spec A2, A9).

---

## 5. Data Model

MySQL, two tables, in the dashboard's own database (on its own hosting account — never a scanned site's database):

```sql
CREATE TABLE accounts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    api_key_hash  CHAR(64) NOT NULL,      -- sha256 of the API key
    created_at    DATETIME NOT NULL
);

CREATE TABLE users (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(255) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,  -- password_hash() output (bcrypt)
    created_at     DATETIME NOT NULL
);

CREATE TABLE findings (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_id       INT NOT NULL REFERENCES accounts(id),
    site_id          VARCHAR(12) NOT NULL,   -- the scanner's manifest-derived site id
    site_label       VARCHAR(255) NULL,      -- human-readable, if available
    scan_id          VARCHAR(64) NOT NULL,
    subject          VARCHAR(512) NOT NULL,  -- from RiskScorer's grouping (path/user_login/page_id/.htaccess)
    severity         ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL,
    composite_score  INT NOT NULL,
    finding_type     VARCHAR(64) NOT NULL,   -- the individual signal, e.g. file_new
    details          JSON NOT NULL,
    scanned_at       DATETIME NOT NULL,
    ingested_at      DATETIME NOT NULL,

    INDEX idx_account_severity (account_id, severity),
    INDEX idx_site (site_id),
    INDEX idx_type (finding_type),
    INDEX idx_scanned_at (scanned_at),
    UNIQUE INDEX idx_dedupe (account_id, scan_id, subject, finding_type)
);
```

One row per **individual finding**, not per scored group — a scan's `ReportBuilder` output groups multiple findings under one `subject`/`severity`/`composite_score`; the ingest endpoint flattens each group's `findings` array into one `findings` table row per entry, repeating the group's `severity`/`composite_score` onto each row. This keeps "filter by finding type" a plain indexed column match instead of a JSON search, while `severity`/`composite_score` still reflect the triage-relevant combined signal, not just one weak individual finding's own weight.

The `idx_dedupe` unique index is what makes the replace-on-push logic (§6) correct: a retried push for the same scan can't create duplicate rows.

---

## 6. Ingest API

`POST /ingest.php`

**Auth:** `Authorization: Bearer <api_key>` header. The server hashes the presented key (SHA-256) and compares against `accounts.api_key_hash` using `hash_equals()` (timing-safe). API keys are generated server-side (high-entropy random, e.g. `bin2hex(random_bytes(32))`) when an account is registered via the Accounts page — never user-chosen, so a fast hash is appropriate (this isn't a password).

**Request body (JSON):**
```json
{
  "meta": { "site_id": "...", "site_label": "...", "scan_id": "...", "scanned_at": "..." },
  "findings": [ /* the report's already-grouped/scored findings array, as ReportBuilder produces it */ ]
}
```

**Behavior:**
1. Validate the API key → 401 if invalid/missing.
2. Validate required fields are present and correctly shaped → 400 if malformed.
3. Within a transaction: `DELETE FROM findings WHERE account_id = ? AND scan_id = ?`, then `INSERT` one row per individual finding across all groups in the payload.
4. Return `200` with a small JSON ack (`{"status":"ok","rows_inserted":N}`).

This delete-then-insert makes a retried push idempotent — the scanner-side `FindingsPusher` can retry on failure without fear of duplicate rows, and the unique index is a second line of defense if the delete/insert ever races.

---

## 7. Dashboard UI

- **`login.php`** — single admin username/password. Password stored bcrypt-hashed (`password_hash()`) in a `users` table (not a config file — keeps the hash out of anything that might get copied/committed alongside code, and leaves room to add a second admin user later without a schema change). Sets a PHP session on success. Every other page requires a valid session, checked via a small shared guard included at the top of each page.
- **`index.php`** (main findings view) — a table of individual findings, default sort: `severity` (CRITICAL first) then `scanned_at` descending. Filter controls: severity (multi-checkbox), account/site (dropdown, populated from `accounts`/distinct `site_id`s), finding type (multi-select), date range (`scanned_at` from/to). Filters compose into one parameterized SQL query. Paginated (e.g. 50/page) since this is meant to accumulate history.
- **Row detail** — expanding a row shows its `details` JSON inline (same evidence the scanner's own report already carries — no new data, just surfaced).
- **`accounts.php`** — logged-in admin can register a new hosting account (name → generates and displays an API key *once*, at creation, never shown again) and revoke an existing one (revoking = the key stops authenticating; existing findings rows stay, for history).

No write/edit actions on findings themselves in this version (confirmed with the user — read-only for v1).

---

## 8. Scanner-Side Change

One new class in the existing scanner, following the exact pattern already established for `Mailer` and `ChecksumClient` (constructor-injected callable, so it's unit-testable without real HTTP):

```php
// src/Reporting/FindingsPusher.php
final class FindingsPusher
{
    /** @param callable(string $url, array $payload, string $apiKey): bool $httpPost */
    public function __construct(
        private readonly mixed $httpPost,
        private readonly string $endpoint,
        private readonly string $apiKey,
    ) {}

    public function push(array $report): bool
    {
        // builds the {meta, findings} payload from $report and calls ($this->httpPost)(...)
    }
}
```

Wired into `bin/run.php` right after each `scanSite()` call, alongside the existing `Mailer`/`DigestQueue` handling. A push failure (non-200, connection error, timeout) is caught, logged via the existing `Logger`, and never affects the scan's own success/failure status or exit code — consistent with how every other injected-callable failure path in this codebase already degrades (checksum fetch failure, mail failure).

**New config file** `config/dashboard.php` (same pattern as `config/mail.php`), holding the ingest endpoint URL and this account's API key — externally configurable per NFR-7, never hardcoded.

---

## 9. Testing

- `FindingsPusher`: unit tests with an injected fake callable — success, non-200 response, thrown/connection-failure case, confirming none of these propagate as an exception out of `push()`.
- `dashboard/`'s ingest endpoint: tests against a test database (SQLite or a disposable test MySQL schema, matching the scanner's own repository-test pattern) covering: valid push creates rows, invalid API key → 401, malformed payload → 400, a second push with the same `scan_id` replaces rather than duplicates rows.
- Dashboard filter-query building: unit-testable in isolation (given a set of filter params, assert the resulting SQL/bindings), independent of the full HTTP/session stack.
- Manual pass on the actual UI once built (login flow, filters, pagination) — full browser-automation testing is not planned for this internal tool.

---

## 10. Security Considerations

- Dashboard login uses a properly hashed password (bcrypt/`password_hash()`), session-based auth, no auth bypass paths.
- API keys are high-entropy, generated server-side, shown once, stored only as a hash.
- The ingest endpoint has no path to modify or delete data outside its own `findings`/`accounts` tables — it cannot reach any scanned site.
- `details` is stored as JSON and rendered client-side — must be HTML-escaped on output to avoid stored-XSS via a finding whose `details` field contains attacker-influenced content (e.g. a malicious filename or plugin slug from a compromised site ending up verbatim in a finding's details, then rendered in the dashboard). This is a real path worth flagging explicitly, given this system's own history of catching exactly this class of "attacker-influenced string reaches somewhere unsafe" bug during the scanner's build (Task 16's plugin-path validation).
- Rate limiting / abuse protection on `ingest.php` is not designed in this version — acceptable for a small number of known, registered accounts; worth revisiting if the account count grows significantly.

---

## 11. Open Questions / Deferred

- Should revoked accounts' historical findings be purged, or kept for audit trail? (Current design: kept — revoking only stops future ingestion.)
- Retention policy for old findings (this design has no automatic pruning) — deferred, not needed for v1.
- "Mark as reviewed" / annotation workflow — deferred to a possible v2, noted as a non-goal above.
