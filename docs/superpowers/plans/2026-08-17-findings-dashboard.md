# Multi-Account Findings Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a central PHP+MySQL app that aggregates security findings pushed from every scanner deployment into one filterable, login-gated view, plus the minimal scanner-side addition needed to push to it.

**Architecture:** A new `dashboard/` directory in this repo — a separately-deployable PHP application (own composer.json, own hand-rolled PSR-4 autoloader, own MySQL database) with two surfaces: an API-key-authenticated ingest endpoint that receives pushed findings and stores them flattened into a `findings` table, and a session-login-gated set of pages for filtering/viewing findings and managing hosting-account API keys. The existing scanner gets one additive class (`FindingsPusher`) wired into `bin/run.php` that POSTs each report to the dashboard after every scan, following the exact injected-callable pattern already used for `Mailer`/`ChecksumClient`.

**Tech Stack:** PHP 8.1+ (no runtime third-party deps, hand-rolled PSR-4 autoloader, matching the existing scanner), PDO (`pdo_mysql` prod / `pdo_sqlite` test), PHPUnit 10 + Composer (dev-only), plain server-rendered PHP pages (no frontend framework, no build step).

**Spec:** `docs/superpowers/specs/2026-08-17-findings-dashboard-design.md` — read this first; it explains why each piece exists and what's explicitly out of scope (multi-user roles, write actions on findings, real-time push, trend analysis).

## Global Constraints

- Target PHP 8.1+ syntax only; do not use 8.2+-only features.
- Zero runtime third-party dependencies in `dashboard/`; ship a hand-rolled `spl_autoload_register` PSR-4 autoloader, same pattern as the existing scanner's `src/Autoload/autoload.php`. Composer/PHPUnit are dev-only.
- All SQL must be portable between MySQL (production) and SQLite (tests) — no MySQL-only functions (`NOW()`, `ON DUPLICATE KEY UPDATE`, etc.) in any repository query. Use PHP-side timestamps (`date('Y-m-d H:i:s')`) passed as bound parameters, and explicit transactions instead of upsert syntax.
- API keys are generated server-side (`bin2hex(random_bytes(32))`), stored only as a SHA-256 hash, compared with `hash_equals()` — never store or log a plaintext key after the moment it's created.
- Passwords are hashed with `password_hash()` (bcrypt) and verified with `password_verify()` — never store or compare plaintext.
- Every HTML-rendering page must `htmlspecialchars(..., ENT_QUOTES)` any value that could contain attacker-influenced content (site labels, subjects, finding details) before output — the spec's Security Considerations section (§10) flags this explicitly given a finding's `details` can originate from a compromised site.
- The dashboard never has any code path that reads from or writes to a scanned WordPress site — it only ever talks to its own MySQL database. This mirrors the scanner's own Audit Mode guarantee and must hold by construction, not by convention.
- All config (DB credentials, session settings) lives in `dashboard/config/*.php`, loaded via a `ConfigLoader`-style `require`, never hardcoded — same externally-configurable pattern as the scanner's `config/*.php`.

---

### Task 1: Dashboard project scaffolding

**Files:**
- Create: `dashboard/composer.json`
- Create: `dashboard/phpunit.xml`
- Create: `dashboard/src/Autoload/autoload.php`
- Create: `dashboard/tests/bootstrap.php`
- Create: `dashboard/tests/Fixtures/SqliteDashboardSchema.php`
- Create: `dashboard/db/schema.sql`
- Create: `dashboard/config/database.php.example`
- Create: `dashboard/.gitignore`
- Test: `tests/Fixtures/SqliteDashboardSchemaTest.php` (a smoke test that the fixture builds cleanly — not testing dashboard logic yet, just that Task 1's foundation works)

**Interfaces:**
- Produces: `AdyaSoft\Dashboard\` PSR-4 namespace rooted at `dashboard/src/`, autoloaded the same way the scanner's `AdyaSoft\Security\` namespace is.
- Produces: `dashboard/tests/Fixtures/SqliteDashboardSchema::createInMemoryDb(): \PDO` — an in-memory SQLite database with `accounts`, `users`, and `findings` tables shaped like `dashboard/db/schema.sql`, for every later task's tests to run real SQL against.

- [ ] **Step 1: Write `dashboard/composer.json`**

```json
{
    "name": "adyasoft/findings-dashboard",
    "description": "Central multi-account findings dashboard for the WordPress security scanner.",
    "type": "project",
    "license": "proprietary",
    "require": {
        "php": ">=8.1"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.5"
    },
    "autoload": {
        "psr-4": {
            "AdyaSoft\\Dashboard\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "AdyaSoft\\Dashboard\\Tests\\": "tests/"
        }
    }
}
```

- [ ] **Step 2: Install dev dependencies**

Run: `cd dashboard && composer install`
Expected: `dashboard/vendor/` created with `phpunit/phpunit`.

- [ ] **Step 3: Write the hand-rolled runtime autoloader**

```php
<?php
// dashboard/src/Autoload/autoload.php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'AdyaSoft\\Dashboard\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/../' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
```

- [ ] **Step 4: Write `dashboard/tests/bootstrap.php`**

```php
<?php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';
```

- [ ] **Step 5: Write `dashboard/phpunit.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="tests/bootstrap.php" colors="true">
    <testsuites>
        <testsuite name="unit">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

- [ ] **Step 6: Write `dashboard/db/schema.sql` (production MySQL schema)**

```sql
-- dashboard/db/schema.sql
-- Run this once against a fresh MySQL database on the dashboard's own
-- hosting account before deploying dashboard/public/.

CREATE TABLE accounts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    api_key_hash  CHAR(64) NOT NULL,
    revoked_at    DATETIME NULL,
    created_at    DATETIME NOT NULL
);

CREATE TABLE users (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(255) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    created_at     DATETIME NOT NULL
);

CREATE TABLE findings (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_id       INT NOT NULL,
    site_id          VARCHAR(12) NOT NULL,
    site_label       VARCHAR(255) NULL,
    scan_id          VARCHAR(64) NOT NULL,
    subject          VARCHAR(512) NOT NULL,
    severity         ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL,
    composite_score  INT NOT NULL,
    finding_type     VARCHAR(64) NOT NULL,
    details          JSON NOT NULL,
    scanned_at       DATETIME NOT NULL,
    ingested_at      DATETIME NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    INDEX idx_account_severity (account_id, severity),
    INDEX idx_site (site_id),
    INDEX idx_type (finding_type),
    INDEX idx_scanned_at (scanned_at),
    UNIQUE INDEX idx_dedupe (account_id, scan_id, subject, finding_type)
);
```

- [ ] **Step 7: Write the SQLite test-fixture equivalent**

```php
<?php
// dashboard/tests/Fixtures/SqliteDashboardSchema.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Fixtures;

final class SqliteDashboardSchema
{
    public static function createInMemoryDb(): \PDO
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $pdo->exec('CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key_hash TEXT NOT NULL,
            revoked_at TEXT NULL,
            created_at TEXT NOT NULL
        )');

        $pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )');

        $pdo->exec('CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            site_id TEXT NOT NULL,
            site_label TEXT NULL,
            scan_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            severity TEXT NOT NULL,
            composite_score INTEGER NOT NULL,
            finding_type TEXT NOT NULL,
            details TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            UNIQUE(account_id, scan_id, subject, finding_type)
        )');

        return $pdo;
    }
}
```

- [ ] **Step 8: Write the smoke test for the fixture**

```php
<?php
// dashboard/tests/Fixtures/SqliteDashboardSchemaTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Fixtures;

use PHPUnit\Framework\TestCase;

final class SqliteDashboardSchemaTest extends TestCase
{
    public function testCreatesAllThreeTables(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();

        $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")
            ->fetchAll(\PDO::FETCH_COLUMN);

        $this->assertContains('accounts', $tables);
        $this->assertContains('users', $tables);
        $this->assertContains('findings', $tables);
    }
}
```

- [ ] **Step 9: Run the test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (1 test)

- [ ] **Step 10: Write `dashboard/config/database.php.example` (checked-in template, real config is gitignored)**

```php
<?php
// dashboard/config/database.php.example
// Copy to database.php and fill in real credentials before deploying.
declare(strict_types=1);

return [
    'dsn' => 'mysql:host=localhost;dbname=findings_dashboard;charset=utf8mb4',
    'user' => 'CHANGE_ME',
    'password' => 'CHANGE_ME',
];
```

- [ ] **Step 11: Write `dashboard/.gitignore`**

```
/vendor/
/config/database.php
.phpunit.result.cache
```

- [ ] **Step 12: Commit**

```bash
git add dashboard/composer.json dashboard/composer.lock dashboard/phpunit.xml \
  dashboard/src/Autoload/autoload.php dashboard/tests/bootstrap.php \
  dashboard/tests/Fixtures/ dashboard/db/schema.sql \
  dashboard/config/database.php.example dashboard/.gitignore
git commit -m "chore: scaffold dashboard project (autoloader, schema, SQLite test fixture)"
```

---

### Task 2: Account repository (API key issuance, listing, revocation)

**Files:**
- Create: `dashboard/src/Accounts/AccountRepository.php`
- Test: `dashboard/tests/Accounts/AccountRepositoryTest.php`

**Interfaces:**
- Consumes: `SqliteDashboardSchema::createInMemoryDb()` from Task 1.
- Produces: `AdyaSoft\Dashboard\Accounts\AccountRepository::__construct(\PDO $pdo)`, methods:
  - `create(string $name): array` — generates a new high-entropy API key, stores its SHA-256 hash, returns `['id' => int, 'name' => string, 'api_key' => string]` where `api_key` is the **plaintext** key (only ever returned here, at creation — never retrievable again).
  - `all(): array` — returns `[['id' => int, 'name' => string, 'revoked' => bool, 'created_at' => string], ...]`, ordered by name. Never includes the key or its hash.
  - `revoke(int $id): void` — sets `revoked_at` to the current time; does not delete the row (so `findings` rows referencing this `account_id` keep working for history, per spec §11).

- [ ] **Step 1: Write the failing test**

```php
<?php
// dashboard/tests/Accounts/AccountRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Accounts;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class AccountRepositoryTest extends TestCase
{
    public function testCreateReturnsPlaintextKeyAndStoresOnlyItsHash(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $repo = new AccountRepository($pdo);

        $created = $repo->create('client-a');

        $this->assertSame('client-a', $created['name']);
        $this->assertIsInt($created['id']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $created['api_key']);

        $stored = $pdo->query('SELECT api_key_hash FROM accounts')->fetchColumn();
        $this->assertSame(hash('sha256', $created['api_key']), $stored);
        $this->assertNotSame($created['api_key'], $stored);
    }

    public function testAllListsAccountsWithoutExposingKeyMaterial(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $repo = new AccountRepository($pdo);
        $repo->create('client-b');
        $repo->create('client-a');

        $accounts = $repo->all();

        $this->assertCount(2, $accounts);
        $this->assertSame('client-a', $accounts[0]['name']);
        $this->assertSame('client-b', $accounts[1]['name']);
        $this->assertFalse($accounts[0]['revoked']);
        $this->assertArrayNotHasKey('api_key', $accounts[0]);
        $this->assertArrayNotHasKey('api_key_hash', $accounts[0]);
    }

    public function testRevokeMarksAccountRevokedWithoutDeletingIt(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $repo = new AccountRepository($pdo);
        $created = $repo->create('client-a');

        $repo->revoke($created['id']);

        $accounts = $repo->all();
        $this->assertCount(1, $accounts);
        $this->assertTrue($accounts[0]['revoked']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/AccountRepositoryTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `AccountRepository`**

```php
<?php
// dashboard/src/Accounts/AccountRepository.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class AccountRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function create(string $name): array
    {
        $apiKey = bin2hex(random_bytes(32));
        $hash = hash('sha256', $apiKey);
        $now = date('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO accounts (name, api_key_hash, revoked_at, created_at) VALUES (?, ?, NULL, ?)'
        );
        $stmt->execute([$name, $hash, $now]);

        return [
            'id' => (int) $this->pdo->lastInsertId(),
            'name' => $name,
            'api_key' => $apiKey,
        ];
    }

    public function all(): array
    {
        $stmt = $this->pdo->query('SELECT id, name, revoked_at, created_at FROM accounts ORDER BY name');

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $results[] = [
                'id' => (int) $row['id'],
                'name' => $row['name'],
                'revoked' => $row['revoked_at'] !== null,
                'created_at' => $row['created_at'],
            ];
        }

        return $results;
    }

    public function revoke(int $id): void
    {
        $stmt = $this->pdo->prepare('UPDATE accounts SET revoked_at = ? WHERE id = ?');
        $stmt->execute([date('Y-m-d H:i:s'), $id]);
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/AccountRepositoryTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/Accounts/AccountRepository.php dashboard/tests/Accounts/AccountRepositoryTest.php
git commit -m "feat: add account repository for API key issuance and revocation"
```

---

### Task 3: API key authenticator

**Files:**
- Create: `dashboard/src/Accounts/ApiKeyAuthenticator.php`
- Test: `dashboard/tests/Accounts/ApiKeyAuthenticatorTest.php`

**Interfaces:**
- Consumes: `AccountRepository` (Task 2) — specifically the `accounts` table shape it writes to.
- Produces: `AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator::__construct(\PDO $pdo)`, method `authenticate(?string $authorizationHeader): ?int` — returns the matching `account_id` on success, or `null` if the header is missing, malformed, doesn't match any non-revoked account's key, or matches a revoked account's key. Expects the header value in the form `Bearer <key>` (case-insensitive on the word `Bearer`). Uses `hash_equals()` for the comparison (never `===`), per the spec's stated timing-safety requirement.

- [ ] **Step 1: Write the failing test**

```php
<?php
// dashboard/tests/Accounts/ApiKeyAuthenticatorTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Accounts;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class ApiKeyAuthenticatorTest extends TestCase
{
    public function testAuthenticatesValidBearerKeyForActiveAccount(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $created = (new AccountRepository($pdo))->create('client-a');

        $auth = new ApiKeyAuthenticator($pdo);

        $this->assertSame($created['id'], $auth->authenticate("Bearer {$created['api_key']}"));
    }

    public function testRejectsMissingHeader(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $auth = new ApiKeyAuthenticator($pdo);

        $this->assertNull($auth->authenticate(null));
    }

    public function testRejectsMalformedHeader(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        (new AccountRepository($pdo))->create('client-a');
        $auth = new ApiKeyAuthenticator($pdo);

        $this->assertNull($auth->authenticate('not-a-bearer-header'));
    }

    public function testRejectsUnknownKey(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        (new AccountRepository($pdo))->create('client-a');
        $auth = new ApiKeyAuthenticator($pdo);

        $this->assertNull($auth->authenticate('Bearer ' . bin2hex(random_bytes(32))));
    }

    public function testRejectsRevokedAccountsKey(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $repo = new AccountRepository($pdo);
        $created = $repo->create('client-a');
        $repo->revoke($created['id']);

        $auth = new ApiKeyAuthenticator($pdo);

        $this->assertNull($auth->authenticate("Bearer {$created['api_key']}"));
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/ApiKeyAuthenticatorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `ApiKeyAuthenticator`**

```php
<?php
// dashboard/src/Accounts/ApiKeyAuthenticator.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class ApiKeyAuthenticator
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function authenticate(?string $authorizationHeader): ?int
    {
        if ($authorizationHeader === null) {
            return null;
        }

        if (preg_match('/^Bearer\s+(.+)$/i', trim($authorizationHeader), $matches) !== 1) {
            return null;
        }

        $providedHash = hash('sha256', $matches[1]);

        $stmt = $this->pdo->query('SELECT id, api_key_hash FROM accounts WHERE revoked_at IS NULL');
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            if (hash_equals($row['api_key_hash'], $providedHash)) {
                return (int) $row['id'];
            }
        }

        return null;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/ApiKeyAuthenticatorTest.php`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/Accounts/ApiKeyAuthenticator.php dashboard/tests/Accounts/ApiKeyAuthenticatorTest.php
git commit -m "feat: add API key authenticator with timing-safe comparison"
```

---

### Task 4: Ingest payload validation and storage

**Files:**
- Create: `dashboard/src/Ingest/IngestPayloadValidator.php`
- Create: `dashboard/src/Ingest/FindingsIngester.php`
- Test: `dashboard/tests/Ingest/IngestPayloadValidatorTest.php`
- Test: `dashboard/tests/Ingest/FindingsIngesterTest.php`

**Interfaces:**
- Consumes: the payload shape the scanner's `FindingsPusher` (Task 10) will send: `{"meta": {"site_id": string, "site_label": ?string, "scan_id": string, "scanned_at": string}, "findings": [{"subject": string, "severity": string, "composite_score": int, "findings": [{"type": string, "details": array, ...}]}]}` — this mirrors `ReportBuilder::build()`'s `findings` array exactly (each entry is one `RiskScorer`-grouped item; each item's own `findings` sub-array holds the individual signal findings that were grouped together).
- Produces: `AdyaSoft\Dashboard\Ingest\IngestPayloadValidator`, method `validate(array $payload): array` — returns `['valid' => bool, 'errors' => string[]]`. Pure function, no I/O.
- Produces: `AdyaSoft\Dashboard\Ingest\FindingsIngester::__construct(\PDO $pdo)`, method `ingest(int $accountId, array $payload): int` — returns the number of rows inserted. Assumes `$payload` already passed `IngestPayloadValidator::validate()`. Deletes any existing rows for `(account_id, scan_id)` before inserting (idempotent replace, per spec §6), all inside one transaction.

- [ ] **Step 1: Write the failing test for `IngestPayloadValidator`**

```php
<?php
// dashboard/tests/Ingest/IngestPayloadValidatorTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Ingest;

use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;
use PHPUnit\Framework\TestCase;

final class IngestPayloadValidatorTest extends TestCase
{
    private function validPayload(): array
    {
        return [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => 'abc123def456-cheap-20260817-100000',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => 'wp-content/uploads/shell.php',
                    'severity' => 'CRITICAL',
                    'composite_score' => 90,
                    'findings' => [
                        ['type' => 'file_new', 'details' => ['size' => 100]],
                        ['type' => 'file_in_uploads_is_php', 'details' => []],
                    ],
                ],
            ],
        ];
    }

    public function testAcceptsAWellFormedPayload(): void
    {
        $validator = new IngestPayloadValidator();

        $result = $validator->validate($this->validPayload());

        $this->assertTrue($result['valid']);
        $this->assertSame([], $result['errors']);
    }

    public function testRejectsMissingMeta(): void
    {
        $payload = $this->validPayload();
        unset($payload['meta']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertNotEmpty($result['errors']);
    }

    public function testRejectsMetaMissingRequiredKey(): void
    {
        $payload = $this->validPayload();
        unset($payload['meta']['scan_id']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('scan_id', $result['errors'][0]);
    }

    public function testRejectsFindingsEntryMissingSeverity(): void
    {
        $payload = $this->validPayload();
        unset($payload['findings'][0]['severity']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
    }

    public function testRejectsIndividualFindingMissingType(): void
    {
        $payload = $this->validPayload();
        unset($payload['findings'][0]['findings'][0]['type']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
    }

    public function testAcceptsEmptyFindingsArray(): void
    {
        $payload = $this->validPayload();
        $payload['findings'] = [];

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertTrue($result['valid']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/IngestPayloadValidatorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `IngestPayloadValidator`**

```php
<?php
// dashboard/src/Ingest/IngestPayloadValidator.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

final class IngestPayloadValidator
{
    public function validate(array $payload): array
    {
        $errors = [];

        if (!isset($payload['meta']) || !is_array($payload['meta'])) {
            $errors[] = 'meta is required and must be an object';
        } else {
            foreach (['site_id', 'scan_id', 'scanned_at'] as $key) {
                if (!isset($payload['meta'][$key]) || !is_string($payload['meta'][$key]) || $payload['meta'][$key] === '') {
                    $errors[] = "meta.{$key} is required and must be a non-empty string";
                }
            }
        }

        if (!isset($payload['findings']) || !is_array($payload['findings'])) {
            $errors[] = 'findings is required and must be an array';
        } else {
            foreach ($payload['findings'] as $index => $group) {
                if (!is_array($group)) {
                    $errors[] = "findings[{$index}] must be an object";
                    continue;
                }

                foreach (['subject', 'severity', 'composite_score', 'findings'] as $key) {
                    if (!array_key_exists($key, $group)) {
                        $errors[] = "findings[{$index}].{$key} is required";
                    }
                }

                if (isset($group['findings']) && is_array($group['findings'])) {
                    foreach ($group['findings'] as $j => $individual) {
                        if (!is_array($individual) || !isset($individual['type'])) {
                            $errors[] = "findings[{$index}].findings[{$j}].type is required";
                        }
                    }
                }
            }
        }

        return ['valid' => $errors === [], 'errors' => $errors];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/IngestPayloadValidatorTest.php`
Expected: PASS (6 tests)

- [ ] **Step 5: Write the failing test for `FindingsIngester`**

```php
<?php
// dashboard/tests/Ingest/FindingsIngesterTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Ingest;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class FindingsIngesterTest extends TestCase
{
    private function payload(string $scanId = 'scan-1'): array
    {
        return [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => $scanId,
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => 'wp-content/uploads/shell.php',
                    'severity' => 'CRITICAL',
                    'composite_score' => 90,
                    'findings' => [
                        ['type' => 'file_new', 'details' => ['size' => 100]],
                        ['type' => 'file_in_uploads_is_php', 'details' => []],
                    ],
                ],
            ],
        ];
    }

    public function testIngestFlattensGroupedFindingsIntoIndividualRows(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $ingester = new FindingsIngester($pdo);

        $rowsInserted = $ingester->ingest($accountId, $this->payload());

        $this->assertSame(2, $rowsInserted);

        $rows = $pdo->query('SELECT * FROM findings ORDER BY finding_type')->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertCount(2, $rows);
        $this->assertSame('file_in_uploads_is_php', $rows[0]['finding_type']);
        $this->assertSame('file_new', $rows[1]['finding_type']);
        $this->assertSame('CRITICAL', $rows[0]['severity']);
        $this->assertSame(90, (int) $rows[0]['composite_score']);
        $this->assertSame('wp-content/uploads/shell.php', $rows[0]['subject']);
        $this->assertSame(['size' => 100], json_decode($pdo->query("SELECT details FROM findings WHERE finding_type = 'file_new'")->fetchColumn(), true));
    }

    public function testIngestingTheSameScanIdAgainReplacesRatherThanDuplicates(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $ingester = new FindingsIngester($pdo);

        $ingester->ingest($accountId, $this->payload('scan-1'));
        $ingester->ingest($accountId, $this->payload('scan-1'));

        $count = (int) $pdo->query('SELECT COUNT(*) FROM findings')->fetchColumn();
        $this->assertSame(2, $count);
    }

    public function testDifferentScanIdsAccumulateSeparately(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $ingester = new FindingsIngester($pdo);

        $ingester->ingest($accountId, $this->payload('scan-1'));
        $ingester->ingest($accountId, $this->payload('scan-2'));

        $count = (int) $pdo->query('SELECT COUNT(*) FROM findings')->fetchColumn();
        $this->assertSame(4, $count);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/FindingsIngesterTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `FindingsIngester`**

```php
<?php
// dashboard/src/Ingest/FindingsIngester.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

final class FindingsIngester
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function ingest(int $accountId, array $payload): int
    {
        $siteId = $payload['meta']['site_id'];
        $siteLabel = $payload['meta']['site_label'] ?? null;
        $scanId = $payload['meta']['scan_id'];
        $scannedAt = $payload['meta']['scanned_at'];
        $ingestedAt = date('Y-m-d H:i:s');

        $this->pdo->beginTransaction();

        try {
            $delete = $this->pdo->prepare('DELETE FROM findings WHERE account_id = ? AND scan_id = ?');
            $delete->execute([$accountId, $scanId]);

            $insert = $this->pdo->prepare(
                'INSERT INTO findings
                    (account_id, site_id, site_label, scan_id, subject, severity, composite_score, finding_type, details, scanned_at, ingested_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $rowsInserted = 0;
            foreach ($payload['findings'] as $group) {
                foreach ($group['findings'] as $individual) {
                    $insert->execute([
                        $accountId,
                        $siteId,
                        $siteLabel,
                        $scanId,
                        (string) $group['subject'],
                        $group['severity'],
                        $group['composite_score'],
                        $individual['type'],
                        json_encode($individual['details'] ?? [], JSON_UNESCAPED_SLASHES),
                        $scannedAt,
                        $ingestedAt,
                    ]);
                    $rowsInserted++;
                }
            }

            $this->pdo->commit();

            return $rowsInserted;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/FindingsIngesterTest.php`
Expected: PASS (3 tests)

- [ ] **Step 9: Run the full dashboard suite**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 10: Commit**

```bash
git add dashboard/src/Ingest/ dashboard/tests/Ingest/
git commit -m "feat: add ingest payload validation and idempotent findings storage"
```

---

### Task 5: Ingest HTTP controller and endpoint

**Files:**
- Create: `dashboard/src/Ingest/IngestController.php`
- Create: `dashboard/src/Db/Connection.php`
- Create: `dashboard/public/ingest.php`
- Test: `dashboard/tests/Ingest/IngestControllerTest.php`

**Interfaces:**
- Consumes: `ApiKeyAuthenticator` (Task 3), `IngestPayloadValidator` + `FindingsIngester` (Task 4).
- Produces: `AdyaSoft\Dashboard\Db\Connection::create(array $config): \PDO` — `$config` is the shape returned by `require config/database.php` (`['dsn' => string, 'user' => string, 'password' => string]`); builds a `PDO` with `ATTR_ERRMODE => ERRMODE_EXCEPTION`.
- Produces: `AdyaSoft\Dashboard\Ingest\IngestController::__construct(ApiKeyAuthenticator $authenticator, IngestPayloadValidator $validator, FindingsIngester $ingester)`, method `handle(?string $authorizationHeader, string $rawBody): array` — returns `['status' => int, 'body' => string]` (a JSON-encoded body). This is the whole request/response logic as a pure function (no superglobals, no `header()` calls) so it's fully unit-testable; `public/ingest.php` is a thin wrapper that reads real superglobals and calls this.

- [ ] **Step 1: Write the failing test for `IngestController`**

```php
<?php
// dashboard/tests/Ingest/IngestControllerTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Ingest;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Ingest\IngestController;
use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class IngestControllerTest extends TestCase
{
    private function validBody(): string
    {
        return json_encode([
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => 'scan-1',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => 'a.php',
                    'severity' => 'HIGH',
                    'composite_score' => 50,
                    'findings' => [['type' => 'file_new', 'details' => []]],
                ],
            ],
        ]);
    }

    private function makeController(\PDO $pdo): IngestController
    {
        return new IngestController(
            new ApiKeyAuthenticator($pdo),
            new IngestPayloadValidator(),
            new FindingsIngester($pdo),
        );
    }

    public function testValidRequestReturns200AndInsertsRows(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", $this->validBody());

        $this->assertSame(200, $result['status']);
        $decoded = json_decode($result['body'], true);
        $this->assertSame('ok', $decoded['status']);
        $this->assertSame(1, $decoded['rows_inserted']);
    }

    public function testMissingApiKeyReturns401(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $controller = $this->makeController($pdo);

        $result = $controller->handle(null, $this->validBody());

        $this->assertSame(401, $result['status']);
    }

    public function testInvalidApiKeyReturns401(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        (new AccountRepository($pdo))->create('client-a');
        $controller = $this->makeController($pdo);

        $result = $controller->handle('Bearer ' . bin2hex(random_bytes(32)), $this->validBody());

        $this->assertSame(401, $result['status']);
    }

    public function testMalformedJsonBodyReturns400(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", '{not valid json');

        $this->assertSame(400, $result['status']);
    }

    public function testPayloadFailingValidationReturns400(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", json_encode(['meta' => []]));

        $this->assertSame(400, $result['status']);
        $decoded = json_decode($result['body'], true);
        $this->assertNotEmpty($decoded['errors']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/IngestControllerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `IngestController`**

```php
<?php
// dashboard/src/Ingest/IngestController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;

final class IngestController
{
    public function __construct(
        private readonly ApiKeyAuthenticator $authenticator,
        private readonly IngestPayloadValidator $validator,
        private readonly FindingsIngester $ingester,
    ) {
    }

    public function handle(?string $authorizationHeader, string $rawBody): array
    {
        $accountId = $this->authenticator->authenticate($authorizationHeader);
        if ($accountId === null) {
            return $this->jsonResponse(401, ['status' => 'error', 'message' => 'invalid or missing API key']);
        }

        $payload = json_decode($rawBody, true);
        if (!is_array($payload)) {
            return $this->jsonResponse(400, ['status' => 'error', 'message' => 'body must be valid JSON']);
        }

        $validation = $this->validator->validate($payload);
        if (!$validation['valid']) {
            return $this->jsonResponse(400, ['status' => 'error', 'errors' => $validation['errors']]);
        }

        $rowsInserted = $this->ingester->ingest($accountId, $payload);

        return $this->jsonResponse(200, ['status' => 'ok', 'rows_inserted' => $rowsInserted]);
    }

    private function jsonResponse(int $status, array $body): array
    {
        return ['status' => $status, 'body' => json_encode($body, JSON_UNESCAPED_SLASHES)];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Ingest/IngestControllerTest.php`
Expected: PASS (5 tests)

- [ ] **Step 5: Implement `Connection` (no dedicated test — thin PDO-construction wrapper, exercised by the end-to-end smoke test in Task 11)**

```php
<?php
// dashboard/src/Db/Connection.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Db;

final class Connection
{
    public static function create(array $config): \PDO
    {
        return new \PDO($config['dsn'], $config['user'] ?? null, $config['password'] ?? null, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        ]);
    }
}
```

- [ ] **Step 6: Write `dashboard/public/ingest.php`**

```php
<?php
// dashboard/public/ingest.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Db\Connection;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Ingest\IngestController;
use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$controller = new IngestController(
    new ApiKeyAuthenticator($pdo),
    new IngestPayloadValidator(),
    new FindingsIngester($pdo),
);

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
$rawBody = file_get_contents('php://input');

$result = $controller->handle($authHeader, $rawBody);

http_response_code($result['status']);
header('Content-Type: application/json');
echo $result['body'];
```

- [ ] **Step 7: Run the full dashboard suite**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 8: Commit**

```bash
git add dashboard/src/Ingest/IngestController.php dashboard/src/Db/Connection.php \
  dashboard/public/ingest.php dashboard/tests/Ingest/IngestControllerTest.php
git commit -m "feat: add ingest HTTP controller and public endpoint"
```

---

### Task 6: Findings repository (filtering and pagination)

**Files:**
- Create: `dashboard/src/Findings/FindingsRepository.php`
- Test: `dashboard/tests/Findings/FindingsRepositoryTest.php`

**Interfaces:**
- Consumes: the `findings` table shape from Task 1/4.
- Produces: `AdyaSoft\Dashboard\Findings\FindingsRepository::__construct(\PDO $pdo)`, method `search(array $filters, int $page, int $perPage): array` — returns `['rows' => array[], 'total' => int]`. `$filters` keys (all optional): `severities` (string[]), `accountId` (?int), `siteId` (?string), `types` (string[]), `from` (?string, compared against `scanned_at`), `to` (?string). Rows are ordered CRITICAL→HIGH→MEDIUM→LOW then `scanned_at` descending, and each row's `details` column is JSON-decoded back into a PHP array before being returned.

- [ ] **Step 1: Write the failing test**

```php
<?php
// dashboard/tests/Findings/FindingsRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Findings;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Findings\FindingsRepository;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class FindingsRepositoryTest extends TestCase
{
    private function seed(\PDO $pdo, int $accountId, string $scanId, string $subject, string $severity, string $type, string $scannedAt): void
    {
        (new FindingsIngester($pdo))->ingest($accountId, [
            'meta' => ['site_id' => 'site1', 'site_label' => null, 'scan_id' => $scanId, 'scanned_at' => $scannedAt],
            'findings' => [[
                'subject' => $subject,
                'severity' => $severity,
                'composite_score' => 50,
                'findings' => [['type' => $type, 'details' => []]],
            ]],
        ]);
    }

    public function testReturnsAllRowsSortedBySeverityThenRecency(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'low.php', 'LOW', 'file_new', '2026-08-17T09:00:00+00:00');
        $this->seed($pdo, $accountId, 'scan-2', 'crit.php', 'CRITICAL', 'file_new', '2026-08-17T08:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search([], 1, 50);

        $this->assertSame(2, $result['total']);
        $this->assertSame('CRITICAL', $result['rows'][0]['severity']);
        $this->assertSame('LOW', $result['rows'][1]['severity']);
    }

    public function testFiltersBySeverity(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'low.php', 'LOW', 'file_new', '2026-08-17T09:00:00+00:00');
        $this->seed($pdo, $accountId, 'scan-2', 'crit.php', 'CRITICAL', 'file_new', '2026-08-17T08:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search(['severities' => ['CRITICAL']], 1, 50);

        $this->assertSame(1, $result['total']);
        $this->assertSame('crit.php', $result['rows'][0]['subject']);
    }

    public function testFiltersByFindingType(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'a.php', 'HIGH', 'file_new', '2026-08-17T09:00:00+00:00');
        $this->seed($pdo, $accountId, 'scan-2', 'b.php', 'HIGH', 'htaccess_diff', '2026-08-17T08:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search(['types' => ['htaccess_diff']], 1, 50);

        $this->assertSame(1, $result['total']);
        $this->assertSame('htaccess_diff', $result['rows'][0]['finding_type']);
    }

    public function testFiltersByDateRange(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'old.php', 'HIGH', 'file_new', '2026-08-01T00:00:00+00:00');
        $this->seed($pdo, $accountId, 'scan-2', 'new.php', 'HIGH', 'file_new', '2026-08-17T00:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search(['from' => '2026-08-10T00:00:00+00:00'], 1, 50);

        $this->assertSame(1, $result['total']);
        $this->assertSame('new.php', $result['rows'][0]['subject']);
    }

    public function testDecodesDetailsBackIntoAnArray(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        (new FindingsIngester($pdo))->ingest($accountId, [
            'meta' => ['site_id' => 'site1', 'site_label' => null, 'scan_id' => 'scan-1', 'scanned_at' => '2026-08-17T09:00:00+00:00'],
            'findings' => [[
                'subject' => 'a.php', 'severity' => 'HIGH', 'composite_score' => 50,
                'findings' => [['type' => 'file_new', 'details' => ['size' => 42]]],
            ]],
        ]);

        $result = (new FindingsRepository($pdo))->search([], 1, 50);

        $this->assertSame(['size' => 42], $result['rows'][0]['details']);
    }

    public function testPaginatesResults(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        for ($i = 0; $i < 5; $i++) {
            $this->seed($pdo, $accountId, "scan-{$i}", "file{$i}.php", 'HIGH', 'file_new', '2026-08-17T09:00:00+00:00');
        }

        $result = (new FindingsRepository($pdo))->search([], 1, 2);

        $this->assertSame(5, $result['total']);
        $this->assertCount(2, $result['rows']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Findings/FindingsRepositoryTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `FindingsRepository`**

```php
<?php
// dashboard/src/Findings/FindingsRepository.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Findings;

final class FindingsRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function search(array $filters, int $page, int $perPage): array
    {
        [$whereSql, $params] = $this->buildWhere($filters);

        $countStmt = $this->pdo->prepare("SELECT COUNT(*) FROM findings {$whereSql}");
        $countStmt->execute($params);
        $total = (int) $countStmt->fetchColumn();

        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $offset = ($page - 1) * $perPage;

        $severityOrder = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
        $sql = "SELECT * FROM findings {$whereSql} ORDER BY {$severityOrder} ASC, scanned_at DESC LIMIT {$perPage} OFFSET {$offset}";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        $rows = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $row['details'] = json_decode($row['details'], true);
            $rows[] = $row;
        }

        return ['rows' => $rows, 'total' => $total];
    }

    private function buildWhere(array $filters): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['severities'])) {
            $placeholders = implode(',', array_fill(0, count($filters['severities']), '?'));
            $where[] = "severity IN ({$placeholders})";
            array_push($params, ...$filters['severities']);
        }

        if (!empty($filters['accountId'])) {
            $where[] = 'account_id = ?';
            $params[] = $filters['accountId'];
        }

        if (!empty($filters['siteId'])) {
            $where[] = 'site_id = ?';
            $params[] = $filters['siteId'];
        }

        if (!empty($filters['types'])) {
            $placeholders = implode(',', array_fill(0, count($filters['types']), '?'));
            $where[] = "finding_type IN ({$placeholders})";
            array_push($params, ...$filters['types']);
        }

        if (!empty($filters['from'])) {
            $where[] = 'scanned_at >= ?';
            $params[] = $filters['from'];
        }

        if (!empty($filters['to'])) {
            $where[] = 'scanned_at <= ?';
            $params[] = $filters['to'];
        }

        $whereSql = $where === [] ? '' : 'WHERE ' . implode(' AND ', $where);

        return [$whereSql, $params];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Findings/FindingsRepositoryTest.php`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/Findings/FindingsRepository.php dashboard/tests/Findings/FindingsRepositoryTest.php
git commit -m "feat: add findings repository with severity/account/type/date filtering"
```

---

### Task 7: Authentication (login, session, bootstrap CLI)

**Files:**
- Create: `dashboard/src/Auth/PasswordAuth.php`
- Create: `dashboard/src/Auth/SessionGuard.php`
- Create: `dashboard/bin/create-user.php`
- Create: `dashboard/public/login.php`
- Create: `dashboard/public/logout.php`
- Test: `dashboard/tests/Auth/PasswordAuthTest.php`

**Interfaces:**
- Consumes: the `users` table shape from Task 1.
- Produces: `AdyaSoft\Dashboard\Auth\PasswordAuth::__construct(\PDO $pdo)`, method `verify(string $username, string $password): ?int` — returns the matching `user_id` on success, `null` if the username doesn't exist or the password doesn't match (`password_verify()`).
- Produces: `AdyaSoft\Dashboard\Auth\SessionGuard` (static methods, thin wrapper over `$_SESSION`): `login(int $userId): void`, `check(): bool`, `currentUserId(): ?int`, `logout(): void`. Not unit-tested (pure `$_SESSION` glue with no branching logic worth testing in isolation) — exercised by the end-to-end smoke test in Task 11.

- [ ] **Step 1: Write the failing test for `PasswordAuth`**

```php
<?php
// dashboard/tests/Auth/PasswordAuthTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Auth;

use AdyaSoft\Dashboard\Auth\PasswordAuth;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class PasswordAuthTest extends TestCase
{
    private function seedUser(\PDO $pdo, string $username, string $password): int
    {
        $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)');
        $stmt->execute([$username, password_hash($password, PASSWORD_BCRYPT), date('Y-m-d H:i:s')]);
        return (int) $pdo->lastInsertId();
    }

    public function testVerifyReturnsUserIdForCorrectCredentials(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $userId = $this->seedUser($pdo, 'admin', 'correct horse battery staple');

        $result = (new PasswordAuth($pdo))->verify('admin', 'correct horse battery staple');

        $this->assertSame($userId, $result);
    }

    public function testVerifyReturnsNullForWrongPassword(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $this->seedUser($pdo, 'admin', 'correct horse battery staple');

        $result = (new PasswordAuth($pdo))->verify('admin', 'wrong password');

        $this->assertNull($result);
    }

    public function testVerifyReturnsNullForUnknownUsername(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();

        $result = (new PasswordAuth($pdo))->verify('nobody', 'anything');

        $this->assertNull($result);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Auth/PasswordAuthTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `PasswordAuth`**

```php
<?php
// dashboard/src/Auth/PasswordAuth.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

final class PasswordAuth
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function verify(string $username, string $password): ?int
    {
        $stmt = $this->pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if ($row === false || !password_verify($password, $row['password_hash'])) {
            return null;
        }

        return (int) $row['id'];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Auth/PasswordAuthTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Implement `SessionGuard`**

```php
<?php
// dashboard/src/Auth/SessionGuard.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

final class SessionGuard
{
    public static function login(int $userId): void
    {
        $_SESSION['user_id'] = $userId;
    }

    public static function check(): bool
    {
        return isset($_SESSION['user_id']);
    }

    public static function currentUserId(): ?int
    {
        return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    }

    public static function logout(): void
    {
        unset($_SESSION['user_id']);
    }
}
```

- [ ] **Step 6: Write `dashboard/bin/create-user.php` (one-time bootstrap CLI — there is no self-registration UI, by design)**

```php
<?php
// dashboard/bin/create-user.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Db\Connection;

$options = getopt('', ['username:', 'password:']);
if (!isset($options['username'], $options['password'])) {
    fwrite(STDERR, "Usage: php bin/create-user.php --username=<name> --password=<password>\n");
    exit(1);
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$hash = password_hash($options['password'], PASSWORD_BCRYPT);
$stmt = $pdo->prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)');
$stmt->execute([$options['username'], $hash, date('Y-m-d H:i:s')]);

fwrite(STDOUT, "User '{$options['username']}' created.\n");
```

- [ ] **Step 7: Write `dashboard/public/login.php`**

```php
<?php
// dashboard/public/login.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Auth\PasswordAuth;
use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $config = require __DIR__ . '/../config/database.php';
    $pdo = Connection::create($config);
    $auth = new PasswordAuth($pdo);

    $username = (string) ($_POST['username'] ?? '');
    $password = (string) ($_POST['password'] ?? '');
    $userId = $auth->verify($username, $password);

    if ($userId !== null) {
        SessionGuard::login($userId);
        header('Location: /index.php');
        exit;
    }

    $error = 'Invalid username or password.';
}
?>
<!DOCTYPE html>
<html>
<head><title>Findings Dashboard — Login</title></head>
<body>
<?php if ($error !== null): ?>
    <p style="color:red;"><?= htmlspecialchars($error, ENT_QUOTES) ?></p>
<?php endif; ?>
<form method="post">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <button type="submit">Log in</button>
</form>
</body>
</html>
```

- [ ] **Step 8: Write `dashboard/public/logout.php`**

```php
<?php
// dashboard/public/logout.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Auth\SessionGuard;

SessionGuard::logout();
header('Location: /login.php');
```

- [ ] **Step 9: Run the full dashboard suite**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 10: Commit**

```bash
git add dashboard/src/Auth/ dashboard/bin/create-user.php \
  dashboard/public/login.php dashboard/public/logout.php dashboard/tests/Auth/
git commit -m "feat: add password authentication, session guard, and user bootstrap CLI"
```

---

### Task 8: Findings view page

**Files:**
- Create: `dashboard/src/Findings/FindingsPageController.php`
- Create: `dashboard/public/index.php`
- Test: `dashboard/tests/Findings/FindingsPageControllerTest.php`

**Interfaces:**
- Consumes: `FindingsRepository` (Task 6).
- Produces: `AdyaSoft\Dashboard\Findings\FindingsPageController::__construct(FindingsRepository $repository)`, method `buildViewModel(array $queryParams): array` — takes a `$_GET`-shaped array, returns `['rows' => array[], 'total' => int, 'page' => int, 'perPage' => int, 'totalPages' => int, 'filters' => array]`. Pure function over its inputs (no superglobal access, no I/O beyond the injected repository) so it's fully unit-testable; `public/index.php` wires it to real `$_GET`/`$_SESSION` and renders HTML.

- [ ] **Step 1: Write the failing test**

```php
<?php
// dashboard/tests/Findings/FindingsPageControllerTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Findings;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Findings\FindingsPageController;
use AdyaSoft\Dashboard\Findings\FindingsRepository;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class FindingsPageControllerTest extends TestCase
{
    private function seedTwoSeverities(\PDO $pdo, int $accountId): void
    {
        $ingester = new FindingsIngester($pdo);
        $ingester->ingest($accountId, [
            'meta' => ['site_id' => 's1', 'site_label' => null, 'scan_id' => 'scan-1', 'scanned_at' => '2026-08-17T09:00:00+00:00'],
            'findings' => [['subject' => 'low.php', 'severity' => 'LOW', 'composite_score' => 10, 'findings' => [['type' => 'file_new', 'details' => []]]]],
        ]);
        $ingester->ingest($accountId, [
            'meta' => ['site_id' => 's1', 'site_label' => null, 'scan_id' => 'scan-2', 'scanned_at' => '2026-08-17T08:00:00+00:00'],
            'findings' => [['subject' => 'crit.php', 'severity' => 'CRITICAL', 'composite_score' => 90, 'findings' => [['type' => 'file_new', 'details' => []]]]],
        ]);
    }

    public function testNoFiltersReturnsAllRows(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seedTwoSeverities($pdo, $accountId);

        $viewModel = (new FindingsPageController(new FindingsRepository($pdo)))->buildViewModel([]);

        $this->assertSame(2, $viewModel['total']);
        $this->assertSame(1, $viewModel['page']);
    }

    public function testSeverityQueryParamFiltersResults(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seedTwoSeverities($pdo, $accountId);

        $viewModel = (new FindingsPageController(new FindingsRepository($pdo)))
            ->buildViewModel(['severity' => ['CRITICAL']]);

        $this->assertSame(1, $viewModel['total']);
        $this->assertSame(['CRITICAL'], $viewModel['filters']['severity']);
    }

    public function testPageQueryParamControlsPagination(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seedTwoSeverities($pdo, $accountId);

        $viewModel = (new FindingsPageController(new FindingsRepository($pdo)))
            ->buildViewModel(['page' => '2']);

        $this->assertSame(2, $viewModel['page']);
    }

    public function testIgnoresUnrecognizedSeverityValues(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seedTwoSeverities($pdo, $accountId);

        $viewModel = (new FindingsPageController(new FindingsRepository($pdo)))
            ->buildViewModel(['severity' => ['NOT_A_REAL_SEVERITY']]);

        $this->assertSame([], $viewModel['filters']['severity']);
        $this->assertSame(2, $viewModel['total']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Findings/FindingsPageControllerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `FindingsPageController`**

```php
<?php
// dashboard/src/Findings/FindingsPageController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Findings;

final class FindingsPageController
{
    private const PER_PAGE = 50;
    private const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

    public function __construct(private readonly FindingsRepository $repository)
    {
    }

    public function buildViewModel(array $queryParams): array
    {
        $severities = isset($queryParams['severity']) && is_array($queryParams['severity'])
            ? array_values(array_intersect($queryParams['severity'], self::VALID_SEVERITIES))
            : [];

        $accountId = isset($queryParams['account_id']) && $queryParams['account_id'] !== ''
            ? (int) $queryParams['account_id']
            : null;

        $siteId = isset($queryParams['site_id']) && $queryParams['site_id'] !== ''
            ? (string) $queryParams['site_id']
            : null;

        $types = isset($queryParams['type']) && is_array($queryParams['type'])
            ? array_values($queryParams['type'])
            : [];

        $from = isset($queryParams['from']) && $queryParams['from'] !== '' ? (string) $queryParams['from'] : null;
        $to = isset($queryParams['to']) && $queryParams['to'] !== '' ? (string) $queryParams['to'] : null;
        $page = isset($queryParams['page']) ? max(1, (int) $queryParams['page']) : 1;

        $result = $this->repository->search(
            [
                'severities' => $severities,
                'accountId' => $accountId,
                'siteId' => $siteId,
                'types' => $types,
                'from' => $from,
                'to' => $to,
            ],
            $page,
            self::PER_PAGE,
        );

        return [
            'rows' => $result['rows'],
            'total' => $result['total'],
            'page' => $page,
            'perPage' => self::PER_PAGE,
            'totalPages' => (int) ceil($result['total'] / self::PER_PAGE),
            'filters' => [
                'severity' => $severities,
                'account_id' => $accountId,
                'site_id' => $siteId,
                'type' => $types,
                'from' => $from,
                'to' => $to,
            ],
        ];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Findings/FindingsPageControllerTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Write `dashboard/public/index.php`**

```php
<?php
// dashboard/public/index.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;
use AdyaSoft\Dashboard\Findings\FindingsPageController;
use AdyaSoft\Dashboard\Findings\FindingsRepository;

if (!SessionGuard::check()) {
    header('Location: /login.php');
    exit;
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$controller = new FindingsPageController(new FindingsRepository($pdo));
$viewModel = $controller->buildViewModel($_GET);
?>
<!DOCTYPE html>
<html>
<head><title>Findings Dashboard</title></head>
<body>
<p><a href="/accounts.php">Manage accounts</a> | <a href="/logout.php">Log out</a></p>
<form method="get">
    <label>Severity:
        <select name="severity[]" multiple>
            <option value="CRITICAL" <?= in_array('CRITICAL', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>CRITICAL</option>
            <option value="HIGH" <?= in_array('HIGH', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>HIGH</option>
            <option value="MEDIUM" <?= in_array('MEDIUM', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>MEDIUM</option>
            <option value="LOW" <?= in_array('LOW', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>LOW</option>
        </select>
    </label>
    <label>From: <input type="date" name="from" value="<?= htmlspecialchars((string) ($viewModel['filters']['from'] ?? ''), ENT_QUOTES) ?>"></label>
    <label>To: <input type="date" name="to" value="<?= htmlspecialchars((string) ($viewModel['filters']['to'] ?? ''), ENT_QUOTES) ?>"></label>
    <button type="submit">Filter</button>
</form>
<table border="1">
<thead><tr><th>Severity</th><th>Site</th><th>Type</th><th>Subject</th><th>Score</th><th>Scanned At</th></tr></thead>
<tbody>
<?php foreach ($viewModel['rows'] as $row): ?>
<tr>
    <td><?= htmlspecialchars($row['severity'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['site_label'] ?? $row['site_id'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['finding_type'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['subject'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars((string) $row['composite_score'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['scanned_at'], ENT_QUOTES) ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<p>Page <?= (int) $viewModel['page'] ?> of <?= max(1, (int) $viewModel['totalPages']) ?> (<?= (int) $viewModel['total'] ?> total findings)</p>
</body>
</html>
```

- [ ] **Step 6: Run the full dashboard suite**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/Findings/FindingsPageController.php dashboard/public/index.php \
  dashboard/tests/Findings/FindingsPageControllerTest.php
git commit -m "feat: add filterable findings view page"
```

---

### Task 9: Accounts management page

**Files:**
- Create: `dashboard/src/Accounts/AccountsPageController.php`
- Create: `dashboard/public/accounts.php`
- Test: `dashboard/tests/Accounts/AccountsPageControllerTest.php`

**Interfaces:**
- Consumes: `AccountRepository` (Task 2).
- Produces: `AdyaSoft\Dashboard\Accounts\AccountsPageController::__construct(AccountRepository $repository)`, methods `handleCreate(string $name): array` (returns the created account including its one-time plaintext `api_key`), `handleRevoke(int $id): void`, `buildViewModel(): array` (returns `['accounts' => array[]]`).

- [ ] **Step 1: Write the failing test**

```php
<?php
// dashboard/tests/Accounts/AccountsPageControllerTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Accounts;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\AccountsPageController;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class AccountsPageControllerTest extends TestCase
{
    public function testHandleCreateReturnsThePlaintextKey(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $controller = new AccountsPageController(new AccountRepository($pdo));

        $created = $controller->handleCreate('client-a');

        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $created['api_key']);
    }

    public function testBuildViewModelListsCreatedAccounts(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $controller = new AccountsPageController(new AccountRepository($pdo));
        $controller->handleCreate('client-a');

        $viewModel = $controller->buildViewModel();

        $this->assertCount(1, $viewModel['accounts']);
        $this->assertSame('client-a', $viewModel['accounts'][0]['name']);
    }

    public function testHandleRevokeMarksAccountRevoked(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $controller = new AccountsPageController(new AccountRepository($pdo));
        $created = $controller->handleCreate('client-a');

        $controller->handleRevoke($created['id']);

        $viewModel = $controller->buildViewModel();
        $this->assertTrue($viewModel['accounts'][0]['revoked']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/AccountsPageControllerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `AccountsPageController`**

```php
<?php
// dashboard/src/Accounts/AccountsPageController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class AccountsPageController
{
    public function __construct(private readonly AccountRepository $repository)
    {
    }

    public function handleCreate(string $name): array
    {
        return $this->repository->create($name);
    }

    public function handleRevoke(int $id): void
    {
        $this->repository->revoke($id);
    }

    public function buildViewModel(): array
    {
        return ['accounts' => $this->repository->all()];
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `cd dashboard && vendor/bin/phpunit tests/Accounts/AccountsPageControllerTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Write `dashboard/public/accounts.php`**

```php
<?php
// dashboard/public/accounts.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\AccountsPageController;
use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;

if (!SessionGuard::check()) {
    header('Location: /login.php');
    exit;
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);
$controller = new AccountsPageController(new AccountRepository($pdo));

$newApiKey = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_name']) && $_POST['create_name'] !== '') {
        $created = $controller->handleCreate((string) $_POST['create_name']);
        $newApiKey = $created['api_key'];
    } elseif (isset($_POST['revoke_id'])) {
        $controller->handleRevoke((int) $_POST['revoke_id']);
    }
}

$viewModel = $controller->buildViewModel();
?>
<!DOCTYPE html>
<html>
<head><title>Manage Accounts</title></head>
<body>
<p><a href="/index.php">Findings</a> | <a href="/logout.php">Log out</a></p>
<?php if ($newApiKey !== null): ?>
    <p><strong>New API key (shown once, copy it now):</strong> <code><?= htmlspecialchars($newApiKey, ENT_QUOTES) ?></code></p>
<?php endif; ?>
<form method="post">
    <label>Account name: <input type="text" name="create_name"></label>
    <button type="submit">Create account</button>
</form>
<table border="1">
<thead><tr><th>Name</th><th>Created</th><th>Status</th><th></th></tr></thead>
<tbody>
<?php foreach ($viewModel['accounts'] as $account): ?>
<tr>
    <td><?= htmlspecialchars($account['name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($account['created_at'], ENT_QUOTES) ?></td>
    <td><?= $account['revoked'] ? 'Revoked' : 'Active' ?></td>
    <td>
        <?php if (!$account['revoked']): ?>
        <form method="post" style="display:inline;">
            <input type="hidden" name="revoke_id" value="<?= (int) $account['id'] ?>">
            <button type="submit">Revoke</button>
        </form>
        <?php endif; ?>
    </td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</body>
</html>
```

- [ ] **Step 6: Run the full dashboard suite**

Run: `cd dashboard && vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/Accounts/AccountsPageController.php dashboard/public/accounts.php \
  dashboard/tests/Accounts/AccountsPageControllerTest.php
git commit -m "feat: add accounts management page (create/revoke API keys)"
```

---

### Task 10: Scanner-side findings pusher

**Files:**
- Create: `src/Reporting/FindingsPusher.php`
- Create: `config/dashboard.php`
- Modify: `bin/run.php`
- Test: `tests/Reporting/FindingsPusherTest.php`

**Interfaces:**
- Consumes: the `$report` array shape `Scanner::scanSite()` returns (`ReportBuilder::build()`'s output — `meta.site_id`, `meta.site_path`, `meta.scan_id`, `meta.scanned_at`, and the `findings` array).
- Produces: `AdyaSoft\Security\Reporting\FindingsPusher::__construct(callable $httpPost, string $endpoint, string $apiKey)` — `$httpPost` has signature `(string $url, array $payload, string $apiKey): bool`, injected so tests never make real HTTP calls. Method `push(array $report): bool` — builds the `{meta, findings}` payload the dashboard's `IngestPayloadValidator` expects and calls the injected callable.

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/Reporting/FindingsPusherTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\FindingsPusher;
use PHPUnit\Framework\TestCase;

final class FindingsPusherTest extends TestCase
{
    private function report(): array
    {
        return [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_path' => '/home/user/public_html',
                'scan_id' => 'abc123def456-cheap-20260817-100000',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'summary' => ['total_findings' => 1, 'by_severity' => ['CRITICAL' => 1, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0]],
            'findings' => [
                ['subject' => 'a.php', 'severity' => 'CRITICAL', 'composite_score' => 90, 'findings' => [['type' => 'file_new', 'details' => []]]],
            ],
        ];
    }

    public function testPushSendsMetaAndFindingsToTheInjectedCallable(): void
    {
        $captured = null;
        $pusher = new FindingsPusher(
            function (string $url, array $payload, string $apiKey) use (&$captured): bool {
                $captured = compact('url', 'payload', 'apiKey');
                return true;
            },
            'https://dashboard.example.com/ingest.php',
            'test-api-key',
        );

        $result = $pusher->push($this->report());

        $this->assertTrue($result);
        $this->assertSame('https://dashboard.example.com/ingest.php', $captured['url']);
        $this->assertSame('test-api-key', $captured['apiKey']);
        $this->assertSame('abc123def456', $captured['payload']['meta']['site_id']);
        $this->assertSame('/home/user/public_html', $captured['payload']['meta']['site_label']);
        $this->assertSame('abc123def456-cheap-20260817-100000', $captured['payload']['meta']['scan_id']);
        $this->assertSame($this->report()['findings'], $captured['payload']['findings']);
    }

    public function testPushReturnsFalseWhenCallableFails(): void
    {
        $pusher = new FindingsPusher(
            fn (string $url, array $payload, string $apiKey): bool => false,
            'https://dashboard.example.com/ingest.php',
            'test-api-key',
        );

        $this->assertFalse($pusher->push($this->report()));
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Reporting/FindingsPusherTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `FindingsPusher`**

```php
<?php
// src/Reporting/FindingsPusher.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class FindingsPusher
{
    /** @param callable(string, array, string): bool $httpPost */
    public function __construct(
        private readonly mixed $httpPost,
        private readonly string $endpoint,
        private readonly string $apiKey,
    ) {
    }

    public function push(array $report): bool
    {
        $payload = [
            'meta' => [
                'site_id' => $report['meta']['site_id'],
                'site_label' => $report['meta']['site_path'] ?? null,
                'scan_id' => $report['meta']['scan_id'],
                'scanned_at' => $report['meta']['scanned_at'],
            ],
            'findings' => $report['findings'],
        ];

        return ($this->httpPost)($this->endpoint, $payload, $this->apiKey);
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Reporting/FindingsPusherTest.php`
Expected: PASS (2 tests)

- [ ] **Step 5: Write `config/dashboard.php`**

```php
<?php
// config/dashboard.php
declare(strict_types=1);

return [
    'endpoint' => 'https://dashboard.example.com/ingest.php',
    'api_key' => 'REPLACE_WITH_KEY_FROM_DASHBOARD_ACCOUNTS_PAGE',
];
```

- [ ] **Step 6: Wire `FindingsPusher` into `bin/run.php`**

The current file (as of this task) reads:

```php
use AdyaSoft\Security\Discovery\ManifestStore;
use AdyaSoft\Security\Discovery\SiteDiscoverer;
use AdyaSoft\Security\Reporting\DigestQueue;
use AdyaSoft\Security\Reporting\Mailer;
use AdyaSoft\Security\Reporting\ReportBuilder;
use AdyaSoft\Security\Scanner;
use AdyaSoft\Security\Support\ConfigLoader;
use AdyaSoft\Security\Support\Logger;
```
and later
```php
$scoringConfig = ConfigLoader::load("{$rootDir}/config/scoring.php");
$mailConfig = ConfigLoader::load("{$rootDir}/config/mail.php");
$sitesConfig = ConfigLoader::load("{$rootDir}/config/sites.php");
```
and later, inside the per-site/per-tier `try` block:
```php
        try {
            $report = $scanner->scanSite($entry['path'], $siteId, $runTier);
            $humanReadable = $reportBuilder->toHumanReadable($report);

            $alerted = $mailer->sendAlertIfNeeded($report, $humanReadable);
            if (!$alerted) {
                $digestQueue->append([
                    'site_id' => $siteId,
                    'scanned_at' => $report['meta']['scanned_at'],
                    'total_findings' => $report['summary']['total_findings'],
                    'degraded' => count($report['meta']['degraded_checks'] ?? []),
                ]);
            }

            $scannedCount++;
        } catch (\Throwable $e) {
```

Make these four changes:

1. Add `use AdyaSoft\Security\Reporting\FindingsPusher;` to the `use` block (alphabetically, after `use AdyaSoft\Security\Reporting\DigestQueue;` and before `use AdyaSoft\Security\Reporting\Mailer;`).

2. After the line `$sitesConfig = ConfigLoader::load("{$rootDir}/config/sites.php");`, add:
```php
$dashboardConfig = ConfigLoader::load("{$rootDir}/config/dashboard.php");
```

3. After the `$mailer = new Mailer(...)` block (after its closing `);`), add:
```php
$findingsPusher = new FindingsPusher(
    static function (string $url, array $payload, string $apiKey): bool {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAuthorization: Bearer {$apiKey}\r\n",
                'content' => json_encode($payload, JSON_UNESCAPED_SLASHES),
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            return false;
        }
        $statusLine = $http_response_header[0] ?? '';
        return (bool) preg_match('/\s200\s/', $statusLine);
    },
    $dashboardConfig['endpoint'],
    $dashboardConfig['api_key'],
);
```

4. Inside the `try` block, immediately after the `$scannedCount++;` line and before the `} catch (\Throwable $e) {` line, add:
```php

            if (!$findingsPusher->push($report)) {
                $logger->warning('failed to push findings to dashboard', ['site_id' => $siteId, 'tier' => $runTier]);
            }
```

A push failure is logged but never affects `$scannedCount`/`$failureCount` or the scan's own success — it's a best-effort side channel, exactly like every other injected-callable failure path in this codebase.

- [ ] **Step 7: Run the full scanner test suite**

Run: `vendor/bin/phpunit`
Expected: PASS (all tests, including the new `FindingsPusherTest`)

- [ ] **Step 8: Commit**

```bash
git add src/Reporting/FindingsPusher.php config/dashboard.php bin/run.php tests/Reporting/FindingsPusherTest.php
git commit -m "feat: push scan findings to the central dashboard after each scan"
```

---

### Task 11: End-to-end smoke test and deployment docs

**Files:**
- Modify: none (verification only)
- Create: `dashboard/README.md`

This task has no new source files — it's a manual, real (not simulated) end-to-end run proving the whole pipeline works together: dashboard serves real HTTP, an account can be created, a scan's findings can be pushed and show up filtered in the UI. Use SQLite (via `config/database.php`'s `dsn`) instead of MySQL for this local smoke test only — production deployment uses MySQL per `dashboard/db/schema.sql`, but this environment has no MySQL server available, and the `Connection`/repository layer is DB-engine-agnostic by design (Global Constraints), so SQLite proves the same code paths.

- [ ] **Step 1: Set up a local SQLite-backed dashboard instance**

```bash
cd dashboard
cp config/database.php.example config/database.php
```

Edit `config/database.php` to point at a local SQLite file instead of MySQL:
```php
<?php
declare(strict_types=1);

return [
    'dsn' => 'sqlite:' . __DIR__ . '/../smoke-test.sqlite',
    'user' => null,
    'password' => null,
];
```

- [ ] **Step 2: Create the schema against the SQLite file**

Since `dashboard/db/schema.sql` is MySQL-flavored (uses `AUTO_INCREMENT`, `ENUM`, `JSON`), for this SQLite smoke test build the schema via a tiny one-off script instead of running `schema.sql` directly:

```bash
php -r '
require __DIR__ . "/src/Autoload/autoload.php";
$config = require __DIR__ . "/config/database.php";
$pdo = AdyaSoft\Dashboard\Db\Connection::create($config);
$pdo->exec("CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, api_key_hash TEXT NOT NULL, revoked_at TEXT NULL, created_at TEXT NOT NULL)");
$pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)");
$pdo->exec("CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, site_id TEXT NOT NULL, site_label TEXT NULL, scan_id TEXT NOT NULL, subject TEXT NOT NULL, severity TEXT NOT NULL, composite_score INTEGER NOT NULL, finding_type TEXT NOT NULL, details TEXT NOT NULL, scanned_at TEXT NOT NULL, ingested_at TEXT NOT NULL, UNIQUE(account_id, scan_id, subject, finding_type))");
echo "schema created\n";
'
```

Expected output: `schema created`

- [ ] **Step 3: Create an admin user and start the dev server**

```bash
php bin/create-user.php --username=admin --password=smoke-test-password
php -S localhost:8765 -t public
```

Expected: `User 'admin' created.` then the server starts listening (leave it running in this terminal; use a second terminal for the remaining steps).

- [ ] **Step 4: Register a hosting account via the Accounts page**

In a second terminal:
```bash
curl -s -c /tmp/dash-cookies.txt -X POST http://localhost:8765/login.php \
  -d 'username=admin' -d 'password=smoke-test-password' -o /dev/null -w '%{http_code}\n'
curl -s -b /tmp/dash-cookies.txt -X POST http://localhost:8765/accounts.php \
  -d 'create_name=smoke-test-account' | grep -o 'New API key.*</code>'
```

Expected: the login curl prints `302` (redirect on success), and the second command's output contains a 64-hex-character API key inside a `<code>` tag. **Copy that key** — it's needed in the next step.

- [ ] **Step 5: Push a findings payload to the ingest endpoint**

```bash
curl -s -X POST http://localhost:8765/ingest.php \
  -H "Authorization: Bearer PASTE_THE_KEY_FROM_STEP_4_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "meta": {"site_id": "abc123def456", "site_label": "smoketest.example.com", "scan_id": "smoke-scan-1", "scanned_at": "2026-08-17T10:00:00+00:00"},
    "findings": [
      {"subject": "wp-content/uploads/shell.php", "severity": "CRITICAL", "composite_score": 90,
       "findings": [{"type": "file_new", "details": {"size": 512}}, {"type": "file_in_uploads_is_php", "details": []}]}
    ]
  }'
```

Expected: `{"status":"ok","rows_inserted":2}`

- [ ] **Step 6: Confirm the pushed findings appear in the filtered dashboard view**

```bash
curl -s -b /tmp/dash-cookies.txt 'http://localhost:8765/index.php?severity[]=CRITICAL'
```

Expected: the HTML output contains `wp-content/uploads/shell.php`, `CRITICAL`, and `smoketest.example.com`.

- [ ] **Step 7: Confirm a non-matching filter correctly excludes it**

```bash
curl -s -b /tmp/dash-cookies.txt 'http://localhost:8765/index.php?severity[]=LOW'
```

Expected: the HTML output does NOT contain `wp-content/uploads/shell.php` (0 total findings for that filter).

- [ ] **Step 8: Stop the dev server and clean up smoke-test artifacts**

```bash
# stop the `php -S` process from Step 3 (Ctrl+C in its terminal)
rm -f dashboard/smoke-test.sqlite dashboard/config/database.php /tmp/dash-cookies.txt
```

`dashboard/config/database.php` is gitignored (Task 1), so removing it just resets the local dev environment — it never gets committed.

- [ ] **Step 9: Write `dashboard/README.md`**

```markdown
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
```

- [ ] **Step 10: Commit**

```bash
git add dashboard/README.md
git commit -m "docs: add dashboard deployment and scanner-connection instructions"
```

---

## Self-Review Notes

- **Spec coverage:** every section of `docs/superpowers/specs/2026-08-17-findings-dashboard-design.md` maps to a task above — §4 Architecture → Tasks 1/10; §5 Data Model → Task 1; §6 Ingest API → Tasks 3-5; §7 Dashboard UI → Tasks 7-9; §8 Scanner-Side Change → Task 10; §9 Testing → covered within every task's TDD steps plus Task 11's end-to-end pass; §10 Security Considerations → API-key hashing (Task 2/3), password hashing (Task 7), `htmlspecialchars` on every rendered value (Tasks 8/9).
- **Deferred (not in this plan, per spec §3.1/§11):** multi-user roles, write/annotation actions on findings, real-time push notifications, retention/pruning policy, historical trend charts.
- **Type consistency:** the `{meta, findings}` payload shape is defined once in Task 4's `IngestPayloadValidator` and consumed identically by `FindingsIngester` (Task 4), `IngestController` (Task 5), and `FindingsPusher` (Task 10) — verified the field names (`site_id`, `site_label`, `scan_id`, `scanned_at`, and each finding group's `subject`/`severity`/`composite_score`/`findings[].type`/`findings[].details`) match exactly across all four.
