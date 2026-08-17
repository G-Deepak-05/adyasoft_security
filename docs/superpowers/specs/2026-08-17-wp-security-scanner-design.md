# Multi-Site WordPress Security Scanner & Remediation System — Spec

**Status:** Draft (PRD) + Architecture Addendum for v0 (Audit Mode, P0 scope)
**Owner:** Security / Engineering

This file has two parts:

1. The original PRD, as given, unmodified.
2. An **Architecture Decisions** addendum, written to fill the gap left by the
   (not-yet-written) "WordPress/Hostinger Security Automation Architecture"
   doc the PRD references. These decisions are scoped to what's needed to
   implement the PRD's **P0 requirements** (the bar for Audit Mode v1 launch,
   per the priority key in §6). P1/P2 items are explicitly deferred — see
   §12 of the addendum.

---

## Part 1: PRD

# Product Requirements Document
## Multi-Site WordPress Security Scanner & Remediation System

**Status:** Draft
**Owner:** Security / Engineering
**Related doc:** WordPress/Hostinger Security Automation Architecture

---

## 1. Summary

A per-account, cron-scheduled scanning system that automatically discovers all WordPress installations across our Hostinger hPanel hosting accounts, detects signs of compromise (malicious files, unauthorized admin accounts, unauthorized pages, altered `.htaccess`/redirects, modified core/plugin files), scores findings by confidence, and reports them centrally — with an explicit read-only Audit Mode first, and a tightly-scoped, mostly human-confirmed Remediation Mode second.

---

## 2. Problem Statement

We host and manage multiple WordPress sites on Hostinger shared/startup/business plans. Sites are repeatedly compromised — attackers create spam pages, inject PHP files, create rogue admin accounts, and alter `.htaccess`/redirects. Detection and cleanup today is 100% manual: someone has to notice a site is compromised, log into hPanel, hunt for bad files/pages/users by hand, and clean them up — once per site, every time. This doesn't scale past a handful of sites and means compromises often sit undetected for days.

**Core pain points:**
- No visibility into compromise until a customer/visitor/Google flags it (e.g., spam pages ranking, browser malware warnings).
- No consistent process — cleanup quality depends on who's doing it and how much time they have.
- No way to tell, across many sites, which ones are currently affected without checking each individually.
- Past cleanups don't reliably fix the entry point, so sites get recompromised.

---

## 3. Goals

1. Automatically discover every WordPress installation across all managed hosting accounts, on a recurring basis, with no manual inventory maintenance.
2. Detect the specific compromise symptoms we've experienced — unauthorized pages, unauthorized admin accounts, injected/modified PHP files, altered `.htaccess`/redirects — with a risk score that separates "worth a human look" from "definitely benign."
3. Cut the time-to-detection for a new compromise from "whenever someone notices" to within one scan interval (target: hours, not days).
4. Cut the manual effort of a compromise investigation by surfacing a scoped, per-site report instead of requiring a full manual sweep of the site.
5. Never destroy legitimate content or lock out legitimate users due to a false positive — safety and reversibility take priority over full automation.
6. Provide a foundation that also helps identify *why* a site was compromised (attack vector), not only what to clean up.

## 3.1 Non-Goals (explicitly out of scope for this system)

- Replacing WordPress/plugin/theme vulnerability patch management — this system detects exploitation, it does not itself find or patch unpatched vulnerabilities before they're used.
- Full automated remediation with no human involvement — by design, destructive actions (delete, disable account) always require a human, indefinitely (not just at launch).
- Root-level/server-level intrusion detection — out of reach given no root access on hPanel hosting; system explicitly triages "this looks like it might be server-level" and hands off to escalation, it does not investigate that scenario itself.
- Real-time (sub-minute) detection/WAF-style blocking — this is a periodic scanner, not an inline firewall.
- Managing hosting accounts that are not WordPress (out of scope by definition).
- A general-purpose vulnerability scanner for third-party dependencies beyond what WP-CLI checksum verification and known-CVE cross-referencing provide.

---

## 4. Users / Personas

| Persona | Needs from this system |
|---|---|
| **Security/ops engineer (primary user)** | A daily/weekly view of which sites have findings, ranked by severity, without visiting every site; a fast way to review and approve/reject queued remediation actions. |
| **Site/account manager** | Confidence that "their" sites are being monitored without needing to understand the internals; occasional notification when their site needs attention. |
| **Incident responder** (may be the same person as security/ops) | Enough forensic detail per finding (timestamps, hashes, file paths, related log excerpts) to determine the attack vector, not just "something's wrong." |
| **Leadership/stakeholder** | Periodic summary: how many sites are clean, how many had findings, trend over time, evidence this is reducing recurrence. |

---

## 5. User Stories

- As a security engineer, I want a single report I can check each morning that lists every site with CRITICAL or HIGH findings, so I don't have to log into hPanel for each site individually.
- As a security engineer, I want new WordPress installations added to any hosting account to be automatically picked up by the next discovery run, so I never have to manually register a new site into the scanner.
- As a security engineer, when a file is flagged CRITICAL, I want it automatically moved to a quarantine location (not deleted) with full metadata, so I can review it later without the risk window staying open in the meantime.
- As a security engineer, I want to see exactly which detection signals contributed to a finding's risk score, so I can judge whether it's a false positive without re-doing the investigation myself.
- As a security engineer, I want unauthorized admin accounts and unauthorized pages surfaced as their own dedicated, high-visibility sections of the report, since these are our most common and most damaging compromise symptoms.
- As a security engineer, I want to run the system in a mode that only reports and never modifies anything, so I can validate detection accuracy before trusting any automated action.
- As a security engineer investigating an incident, I want the report to include enough context (file hash, first-seen timestamp, related access-log excerpts if available) to help identify how the attacker got in, not just what they did.
- As an account/site manager, I want to be notified only when something actually needs my attention, not on every routine clean scan, so alert fatigue doesn't set in.
- As a security engineer, I never want the system to delete a page, delete/disable a user, or permanently delete a file without my explicit approval, regardless of how confident the detection is.

---

## 6. Functional Requirements

Numbered `FR-x`, grouped by capability. Priority: **P0** = required for Audit Mode v1 launch, **P1** = required before Remediation Mode launch, **P2** = post-launch enhancement.

### 6.1 Discovery
- **FR-1 (P0):** System scans each hosting account's directory tree and identifies every distinct WordPress installation by presence of `wp-config.php` co-located with `wp-content/`, `wp-admin/`, `wp-includes/`.
- **FR-2 (P0):** System maintains a persistent per-account manifest of known installations (path, first-seen date, site identifier) and re-runs discovery on a recurring schedule to catch newly added sites.
- **FR-3 (P1):** System flags when a previously-known installation is no longer found (e.g., possibly removed or moved) rather than silently dropping it from tracking.

### 6.2 File-level detection
- **FR-4 (P0):** System builds and maintains a per-site file baseline (path, SHA-256 hash, size, mtime, permissions) captured after a confirmed-clean state.
- **FR-5 (P0):** System detects files that are new, modified, or deleted relative to the baseline on each scan.
- **FR-6 (P0):** System flags any PHP-executable file located under `wp-content/uploads/` as inherently high-suspicion.
- **FR-7 (P0):** System flags any file present in `wp-admin/` or `wp-includes/` that is not part of the official WordPress core release manifest for the installed version.
- **FR-8 (P0):** System performs pattern/entropy analysis on PHP files to detect obfuscation indicators (chained encode/decode calls, high-entropy string literals, dynamic function invocation, direct user-input-to-exec-function flows).
- **FR-9 (P0):** System computes a composite risk score per finding, combining multiple independent signals (see architecture doc §5), rather than flagging on any single signal alone.
- **FR-10 (P0):** System flags any new file appearing in `mu-plugins/`.
- **FR-11 (P1):** System supports per-site whitelisting of confirmed-benign files/hashes so they stop re-alerting on subsequent scans.

### 6.3 WordPress core/plugin/theme integrity
- **FR-12 (P0):** System runs WP-CLI core checksum verification against official WordPress.org checksums where WP-CLI is available on the hosting plan.
- **FR-13 (P0):** System runs WP-CLI plugin checksum verification for WordPress.org-hosted plugins where available.
- **FR-14 (P1):** System maintains first-seen baseline hashes for plugins/themes without official checksums (premium/custom) and diffs against that baseline.
- **FR-15 (P1):** System clearly labels findings as "checksum-verified" vs. "baseline-diff-only" so reviewers understand the confidence difference.

### 6.4 User/account detection
- **FR-16 (P0):** System retrieves the current list of WordPress administrator (and optionally editor+) accounts per site.
- **FR-17 (P0):** System compares the current admin roster against a maintained known-good roster per site and flags any account not on that list.
- **FR-18 (P0):** System flags accounts created since the last confirmed-clean scan, regardless of whether they're on the known-good list (to catch a compromised known account being used to create a new one).
- **FR-19 (P1):** System flags suspicious username/email patterns (generic support-style usernames, mismatched email domains) as a secondary signal, not a standalone trigger.

### 6.5 Page/post detection
- **FR-20 (P0):** System maintains a baseline of expected pages/posts per site (title, slug, author, publish date, content hash).
- **FR-21 (P0):** System detects newly created or recently modified pages/posts relative to the baseline.
- **FR-22 (P0):** System flags pages with unexpected authorship (author not matching known content contributors) as an elevated-risk signal.
- **FR-23 (P1):** System applies keyword/category heuristics (common spam categories — gambling, loans, pharma, crypto-scam terms) as an additional signal that increases, but does not solely determine, risk score.
- **FR-24 (P1):** System supports marking specific detected pages as "reviewed — legitimate" to add them to the baseline without needing a full rescan/rebaseline.

### 6.6 `.htaccess` / redirect detection
- **FR-25 (P0):** System maintains a baseline copy of each site's `.htaccess` and flags any diff.
- **FR-26 (P0):** System parses rewrite/redirect rules and flags rules pointing to external domains not previously present.
- **FR-27 (P1):** System distinguishes between rule additions, modifications, and full-file replacement, since these imply different levels of confidence/severity.

### 6.7 Risk scoring & reporting
- **FR-28 (P0):** Every finding is assigned a severity band (LOW/MEDIUM/HIGH/CRITICAL) derived from the composite score, using a documented, tunable scoring model.
- **FR-29 (P0):** System generates a structured (JSON) report per scan per site, and a human-readable summary rendering.
- **FR-30 (P0):** System supports centralized delivery of reports (e.g., email and/or push to a shared store) without requiring cross-account execution access.
- **FR-31 (P0):** System sends an alert (email at minimum) when any CRITICAL/HIGH finding appears, and suppresses routine no-finding notifications to a periodic digest instead.
- **FR-32 (P1):** System retains historical scan results per site to support trend analysis (e.g., recurring-incident sites).
- **FR-33 (P2):** System provides a simple aggregated dashboard/view across all sites' current risk status (could be a generated static page or lightweight app, not necessarily real-time).

### 6.8 Modes & remediation
- **FR-34 (P0):** System supports an explicit **Audit Mode** that performs all detection above with zero write/modify/delete actions against any scanned site.
- **FR-35 (P0):** Audit Mode is the default; Remediation Mode requires explicit opt-in per site.
- **FR-36 (P1):** In Remediation Mode, the system may automatically move (not delete) CRITICAL-band file findings into a non-web-accessible quarantine location.
- **FR-37 (P1):** Quarantine actions preserve original path, timestamp, SHA-256 hash, detection reasons/score, original permissions, and scan ID as metadata alongside the quarantined file.
- **FR-38 (P1):** All other remediation actions (disabling plugins, restoring `.htaccess`, disabling accounts, deleting pages, permanently deleting quarantined files) are queued for explicit human approval and never executed automatically, regardless of confidence score, indefinitely.
- **FR-39 (P1):** System provides a `--dry-run` capability within Remediation Mode that reports intended actions without performing them.
- **FR-40 (P2):** System provides a simple approval mechanism (CLI flag, or a lightweight review UI) for the human-confirmation queue rather than requiring manual file operations.

### 6.9 Investigation support
- **FR-41 (P1):** For each finding, the system captures/links relevant evidence useful for attack-vector analysis (e.g., file first-seen timestamp, related web-server access-log excerpts around that timestamp, where those logs are accessible).
- **FR-42 (P2):** System cross-references installed plugin/theme versions against a known-vulnerability source to flag plugins that were vulnerable as of the approximate compromise window.

---

## 7. Non-Functional Requirements

- **NFR-1 (Safety/reversibility):** No automated action in any mode may be irreversible without human confirmation. Quarantine (move) is the only automated write action permitted in v1.
- **NFR-2 (Portability):** Must run using only capabilities available on Hostinger Shared, Startup, and Business hPanel plans without requiring root or provider-side API access beyond what's documented as available. Must not assume SSH is present (Shared/Startup typically lack it).
- **NFR-3 (Resource footprint):** Must operate within shared-hosting CPU/resource limits — scans must be schedulable in a staggered fashion and must not risk account throttling or suspension.
- **NFR-4 (Isolation):** A scan of one site/account must not require or gain access to another customer's or another account's data; cross-account centralization happens only via each site pushing its own report outward.
- **NFR-5 (Auditability):** Every scan run, every finding, and every action taken (including quarantines) must be logged with enough detail to reconstruct what happened and when, for later incident review.
- **NFR-6 (Low false-positive tolerance for automated actions):** The bar for any automated action (even quarantine) must be tuned, via a documented Audit Mode observation period, before being enabled — no automated action ships without that validation period having occurred for that site.
- **NFR-7 (Maintainability):** Detection rules, scoring weights, and baselines must be externally configurable (not hardcoded) so they can be tuned per-site without code changes.
- **NFR-8 (Timeliness):** High-value, low-cost checks (users, pages, `.htaccess`) must run frequently enough (target: every 1–4 hours) to materially reduce time-to-detection versus the current fully-manual process.

---

## 8. Success Metrics

| Metric | Baseline (today) | Target |
|---|---|---|
| Mean time-to-detection of a new compromise | Unmeasured / reactive (customer or Google flags it) | ≤ 1 scan interval (hours) |
| Manual investigation time per confirmed incident | Hours (full manual sweep) | Minutes (review pre-scored report) |
| False-positive rate on CRITICAL findings during Audit Mode tuning | N/A | < 5% before enabling any automated action on a given site |
| % of sites under active monitoring | 0% (manual only) | 100% of managed WordPress installations within [target timeframe] |
| Recurrence rate (same site recompromised within 90 days) | Unmeasured | Measurable decrease post attack-vector remediation (Section 14 of architecture doc) |
| Legitimate content/accounts incorrectly removed by the system | N/A (no automation today) | Zero, at any point — this is a hard requirement, not a target to approach |

---

## 9. Scope & Phasing (ties to architecture doc §17)

- **v0 / Phase 0–1:** Discovery + baseline capture + Audit Mode detection across all six detection categories (files, core/plugin integrity, users, pages, `.htaccess`, risk scoring). Reporting via email. No remediation.
- **v1 / Phase 2–4:** Centralized report delivery/alerting live; root-cause investigation tooling (FR-41/42) for currently-compromised sites; hardening pass applied.
- **v2 / Phase 5–6:** Remediation Mode (CRITICAL-file-quarantine-only) piloted on one site, then rolled out account by account.
- **v3 / Phase 7+ (post-launch, P2 items):** Aggregated dashboard, historical trend reporting, expanded human-approval workflow tooling, CVE cross-referencing.

---

## 10. Risks & Open Questions

- **Risk:** False positives during early tuning could cause alert fatigue and erode trust in the system before Remediation Mode is even reached. *Mitigation:* mandatory multi-week Audit-Mode-only period per site (NFR-6) before any automated action is enabled.
- **Risk:** Resource throttling on shared hosting if scans are too frequent/heavy. *Mitigation:* staggered scheduling, tiered scan frequency (cheap checks hourly, expensive checks daily) per architecture doc §12.
- **Open question:** Does every managed hosting account have Python available, or is PHP-only assumed for some tiers? Needs confirmation before finalizing implementation language per account.
- **Open question:** What's the actual log retention window available via hPanel per plan tier — this bounds how much FR-41 (attack-vector evidence capture) can retroactively help versus only prospectively.
- **Open question:** Where does the human-approval queue live for v1 — is a simple file/email-based approval (P1) sufficient at current scale, or is a lightweight review UI (P2, FR-40) needed sooner than planned?
- **Risk:** A site owner disabling/ignoring alerts over time. *Mitigation:* digest reporting cadence (FR-31) keeps visibility even absent active incidents, and periodic leadership summary (Section 4) creates an accountability loop.

---

## 11. Out-of-Scope Escalation Path

If detection surfaces evidence suggestive of a hosting-platform/root-level compromise (per architecture doc §13) rather than a WordPress-level one, this system's role is to **flag and hand off**, not investigate further — the report should clearly mark such findings as "escalate to Hostinger" rather than attempt automated remediation, since that scenario is explicitly out of this system's scope (Section 3.1).

---

## Part 2: Architecture Decisions Addendum (v0, P0 scope)

No architecture doc exists yet. These decisions resolve the PRD's open questions and NFRs for the **P0 (Audit Mode launch)** requirement set only, and stand in for the referenced architecture doc for this scope. Written 2026-08-17.

### A1. Language & runtime
PHP, targeting **PHP 8.1+ compatible syntax** (avoid 8.2+/8.3+-only features). PHP is present on every WordPress-capable Hostinger tier by definition (WordPress itself requires it); Python's availability is not guaranteed on Shared/Startup, so it's ruled out (resolves PRD §10 open question).

### A2. Deployment & scheduling model — no SSH required
One copy of the scanner application is deployed per hosting account, as a directory **sibling to `public_html`** (e.g. `~/security-scanner/`), placed there once via FTP/File Manager/git — no SSH needed for deployment. Execution is triggered by **hPanel's native Cron Jobs** feature (configured through the panel UI, not a shell), which invokes `php` directly:

```
php ~/security-scanner/bin/run.php --checks=cheap   # hourly
php ~/security-scanner/bin/run.php --checks=expensive  # daily
```

This satisfies NFR-2 (no SSH/root assumption), NFR-4 (each account's cron runs its own isolated instance; nothing is shared or centrally executed), and NFR-8/NFR-3 (tiered frequency: cheap checks hourly, expensive checks daily, via two cron entries with staggered minute offsets across accounts).

### A3. No shell_exec/exec/proc_open/system, anywhere
Shared hosting frequently disables these functions (`disable_functions` in php.ini), and relying on shelling out to WP-CLI would make FR-12/13 unreliable and unpredictable across accounts. The scanner never shells out. This also sidesteps the "is WP-CLI available" branch entirely: instead of WP-CLI, core/plugin checksum verification (FR-12/13, A5 below) is implemented directly in PHP against WordPress.org's public checksum APIs, which is a faithful, dependency-free substitute for "WP-CLI checksum verification... where WP-CLI is available."

### A4. Data access — direct-to-MySQL, not a WordPress bootstrap
Bootstrapping WordPress itself (`require wp-load.php`) to read users/pages is unsafe across *multiple* sites in one long-lived PHP process, because WordPress core defines global constants (`ABSPATH`, `WPINC`, etc.) that collide on a second `require` for a different site. Instead:

- The scanner parses each site's `wp-config.php` **as text** (regex, not `include`/`require` — including it would trigger a full WP bootstrap via its trailing `require_once ABSPATH.'wp-settings.php'`) to extract `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, and `$table_prefix`.
- It then opens a fresh `PDO` MySQL connection per site and queries `{prefix}users`, `{prefix}usermeta`, `{prefix}posts`, `{prefix}options` directly for user/role, page, and active-plugin data.
- **Documented risk:** non-standard `wp-config.php` layouts (credentials pulled from `getenv()`, environment files, etc.) may fail to parse. When parsing fails, the site is flagged `needs_manual_config` in the report and DB-backed checks (users, pages, active-plugin list) are skipped for that site *only* — file-level and `.htaccess` checks, which don't need DB access, still run.
- This is a well-established pattern for external, out-of-process WordPress tooling (backup tools, security scanners) and keeps every site's scan fully isolated from every other site's in the same process (supports NFR-4).

### A5. Core/plugin integrity via WordPress.org APIs (no WP-CLI)
- Core: `GET https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US` returns the official `{relative_path: sha256}` manifest for that exact core version. Any file under `wp-admin/`/`wp-includes/` not in that manifest, or present with a different hash, is flagged (FR-7, FR-12). Installed version is read from `wp-includes/version.php` (safe to `include` — it only sets a couple of scalar variables, no bootstrap side effects).
- Plugins: `GET https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json` provides the same manifest shape per WordPress.org-hosted plugin (FR-13). Plugin slug/version comes from the `active_plugins` option read via A4.
- Local file hashes are computed with pure PHP `hash_file('sha256', ...)` — no shelling out.

### A6. Storage layout
All scanner state lives under `~/security-scanner/data/`, a sibling of `public_html`, so it is **outside the web docroot and never web-accessible** by construction (no reliance on a `.htaccess` deny rule):

```
security-scanner/
  data/
    manifest.json                     # FR-2/FR-3 site manifest
    sites/<site_id>/
      baseline/{files,pages,htaccess,users}.json
      scans/<scan_id>.json            # FR-29 structured report
      scans/<scan_id>.log             # NFR-5 audit log
```

### A7. Configuration (NFR-7)
Scoring weights, severity-band thresholds, mail recipients/cadence, and per-site known-good user rosters live in PHP config files under `config/`, loaded by a `ConfigLoader` — never hardcoded in detector logic, so they're tunable without a code change.

### A8. Reporting & alerting (FR-29/30/31) — email only in this plan
Each scan produces a structured JSON report plus a rendered human-readable summary. Delivery for this plan is **email only** (PHP `mail()`/SMTP): immediate send per-site when any CRITICAL/HIGH finding exists; clean scans accumulate into a daily digest instead of alerting individually. A shared central store / dashboard (FR-33, P2) is out of scope for this plan.

### A9. No runtime third-party dependencies
The scanner ships with **zero third-party runtime dependencies** — a small hand-rolled PSR-4 `spl_autoload_register` autoloader is committed to the repo, so deployment is a plain file copy with no build step and no server-side `composer install`. Composer and PHPUnit are **dev-only** tooling used to run the test suite in this repo; they are never required on the hosting account.

### A10. Mode enforcement (FR-34/35, NFR-1)
This plan implements **Audit Mode only**: there is no write/modify/delete code path anywhere in the codebase for this scope, so the "no automated action" guarantee holds by construction, not by a runtime flag that could be misconfigured. `bin/run.php` records `mode: "audit"` in every report's metadata. Remediation Mode (FR-36-40) is a future plan, built additively (new code, not a flag flip on this code).

### A11. Scope of this plan
This plan implements exactly the PRD's **P0** requirements (the documented bar for "Audit Mode v1 launch"):
FR-1, FR-2, FR-4, FR-5, FR-6, FR-7, FR-8, FR-9, FR-10, FR-12, FR-13, FR-16, FR-17, FR-18, FR-20, FR-21, FR-22, FR-25, FR-26, FR-28, FR-29, FR-30, FR-31, FR-34, FR-35 — governed throughout by NFR-1 through NFR-8.

Explicitly **out of scope**, deferred to follow-up plans: FR-3, FR-11, FR-14, FR-15, FR-19, FR-23, FR-24, FR-27, FR-32, FR-33 (all P1/P2), and all of §6.8 Remediation (FR-36–40) and §6.9 Investigation support (FR-41/42), per PRD §9's own v1/v2/v3 phasing.

### A12. Testing strategy
Business logic (config parsing, wp-config.php credential parsing, baseline diffing, entropy analysis, risk scoring, report rendering) is pure-PHP and unit-tested with PHPUnit using fixture files/arrays — no live services needed. The MySQL-backed repository layer is tested against an **in-memory SQLite** database (`pdo_sqlite`, confirmed available) seeded with `wp_users`/`wp_usermeta`/`wp_posts`/`wp_options`-shaped fixture tables, exercising real SQL instead of a hand-written fake. Production use is MySQL via `pdo_mysql`. End-to-end verification against a real Hostinger MySQL instance is manual and outside this repo's automated test suite.
