# WordPress Security Scanner — Audit Mode (v0, P0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a per-hosting-account, cron-driven, read-only WordPress compromise scanner (discovery, file/core/plugin/user/page/htaccess detection, composite risk scoring, JSON + email reporting) covering every P0 requirement in the spec, with zero write/delete code paths.

**Architecture:** A dependency-free PHP 8.1+ application deployed as a sibling directory to `public_html` on each Hostinger hPanel account, triggered by native hPanel Cron Jobs (`php bin/run.php --checks=cheap|expensive|all`). Detectors read site data three ways: filesystem walk (files/htaccess), direct PDO MySQL connection using credentials parsed out of `wp-config.php` (users/pages/plugins), and the WordPress.org checksums HTTP API (core/plugin integrity) — never WP-CLI, never `shell_exec`. All state lives outside the web docroot as JSON. A composite risk scorer combines per-detector signals into a severity band; a report builder renders JSON + human-readable output; a mailer sends immediate alerts on CRITICAL/HIGH and a daily digest otherwise.

**Tech Stack:** PHP 8.1+ (no runtime third-party deps, hand-rolled PSR-4 autoloader), PDO (`pdo_mysql` prod / `pdo_sqlite` test), PHPUnit 10 + Composer (dev-only), hPanel Cron Jobs.

**Spec:** `docs/superpowers/specs/2026-08-17-wp-security-scanner-design.md` (PRD + Architecture Decisions Addendum — read both; the addendum's A1–A12 govern every task below).

## Global Constraints

- Target PHP 8.1+ syntax only; do not use 8.2+-only features (spec A1).
- Never call `exec()`, `shell_exec()`, `proc_open()`, `system()`, `popen()`, or shell out to WP-CLI anywhere (spec A3).
- Never `include`/`require` a site's `wp-config.php` or `wp-load.php` (triggers a real WP bootstrap and collides across sites in one process) — parse `wp-config.php` as text only (spec A4).
- Zero runtime third-party dependencies; ship a hand-rolled `spl_autoload_register` PSR-4 autoloader. Composer/PHPUnit are dev-only (spec A9).
- All persisted state (manifest, baselines, scans, logs) lives under `data/`, a sibling of `public_html`, never under a web-servable path (spec A6).
- All scoring weights, severity thresholds, mail settings, and known-good rosters are externally configurable via `config/*.php`, never hardcoded in detector logic (spec A7, NFR-7).
- No write/modify/delete code path exists anywhere in this codebase — Audit Mode only (spec A10, FR-34/35, NFR-1).
- Every scan run and every finding must be logged via `Logger` (NFR-5).
- A detector operating on one site must never read or write another site's data (NFR-4).
- This plan implements exactly the P0 requirements listed in spec A11. Do not implement FR-3, FR-11, FR-14, FR-15, FR-19, FR-23, FR-24, FR-27, FR-32, FR-33, FR-36–42 — they are out of scope for this plan.

---

### Task 1: Project scaffolding & shared foundations

**Files:**
- Create: `composer.json`
- Create: `phpunit.xml`
- Create: `src/Autoload/autoload.php`
- Create: `src/Support/Logger.php`
- Create: `src/Support/ConfigLoader.php`
- Create: `config/scoring.php`
- Create: `config/mail.php`
- Create: `config/sites.php`
- Create: `bin/run.php` (stub only — real wiring in Task 16)
- Create: `.gitignore`
- Create: `README.md`
- Test: `tests/Support/LoggerTest.php`
- Test: `tests/Support/ConfigLoaderTest.php`
- Test: `tests/bootstrap.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\Support\Logger` with `__construct(string $logFilePath)`, `info(string $message, array $context = []): void`, `warning(...)`, `error(...)`. Each call appends one JSON line: `{"ts":..., "level":..., "message":..., "context":...}`.
- Produces: `AdyaSoft\Security\Support\ConfigLoader` with `static load(string $configPath): array` — requires the PHP file and returns the array it returns (config files are plain `<?php return [...];`).

- [ ] **Step 1: Write `composer.json` (dev-only tooling, PSR-4 mapped to `src/`, autoload-dev to `tests/`)**

```json
{
    "name": "adyasoft/security-scanner",
    "description": "Multi-site WordPress security scanner (Audit Mode).",
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
            "AdyaSoft\\Security\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "AdyaSoft\\Security\\Tests\\": "tests/"
        }
    }
}
```

- [ ] **Step 2: Install dev dependencies**

Run: `composer install`
Expected: `vendor/` created with `phpunit/phpunit` and Composer's own PSR-4 autoloader (used only in dev/test — see Step 3 for the deploy-time autoloader).

- [ ] **Step 3: Write the hand-rolled runtime autoloader (no Composer needed on the host)**

```php
<?php
// src/Autoload/autoload.php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'AdyaSoft\\Security\\';
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

- [ ] **Step 4: Write `tests/bootstrap.php` to use the same runtime autoloader (not Composer's) so tests exercise real deploy behavior**

```php
<?php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';
```

- [ ] **Step 5: Write `phpunit.xml`**

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

- [ ] **Step 6: Write the failing test for `Logger`**

```php
<?php
// tests/Support/LoggerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Support;

use AdyaSoft\Security\Support\Logger;
use PHPUnit\Framework\TestCase;

final class LoggerTest extends TestCase
{
    private string $logFile;

    protected function setUp(): void
    {
        $this->logFile = sys_get_temp_dir() . '/scanner-log-' . uniqid('', true) . '.jsonl';
    }

    protected function tearDown(): void
    {
        if (is_file($this->logFile)) {
            unlink($this->logFile);
        }
    }

    public function testInfoAppendsOneJsonLineWithLevelMessageAndContext(): void
    {
        $logger = new Logger($this->logFile);

        $logger->info('scan started', ['site_id' => 'site-a']);

        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES);
        $this->assertCount(1, $lines);

        $decoded = json_decode($lines[0], true);
        $this->assertSame('info', $decoded['level']);
        $this->assertSame('scan started', $decoded['message']);
        $this->assertSame('site-a', $decoded['context']['site_id']);
        $this->assertArrayHasKey('ts', $decoded);
    }

    public function testMultipleCallsAppendRatherThanOverwrite(): void
    {
        $logger = new Logger($this->logFile);

        $logger->info('first');
        $logger->warning('second');
        $logger->error('third');

        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES);
        $this->assertCount(3, $lines);
        $this->assertSame('warning', json_decode($lines[1], true)['level']);
        $this->assertSame('error', json_decode($lines[2], true)['level']);
    }
}
```

- [ ] **Step 7: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Support/LoggerTest.php`
Expected: FAIL — class `AdyaSoft\Security\Support\Logger` not found.

- [ ] **Step 8: Implement `Logger`**

```php
<?php
// src/Support/Logger.php
declare(strict_types=1);

namespace AdyaSoft\Security\Support;

final class Logger
{
    public function __construct(private readonly string $logFilePath)
    {
    }

    public function info(string $message, array $context = []): void
    {
        $this->write('info', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->write('warning', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->write('error', $message, $context);
    }

    private function write(string $level, string $message, array $context): void
    {
        $dir = dirname($this->logFilePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        $line = json_encode([
            'ts' => date('c'),
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ], JSON_UNESCAPED_SLASHES);

        file_put_contents($this->logFilePath, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
```

- [ ] **Step 9: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Support/LoggerTest.php`
Expected: PASS (2 tests)

- [ ] **Step 10: Write the failing test for `ConfigLoader`**

```php
<?php
// tests/Support/ConfigLoaderTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Support;

use AdyaSoft\Security\Support\ConfigLoader;
use PHPUnit\Framework\TestCase;

final class ConfigLoaderTest extends TestCase
{
    public function testLoadReturnsArrayFromConfigFile(): void
    {
        $path = sys_get_temp_dir() . '/scanner-config-' . uniqid('', true) . '.php';
        file_put_contents($path, "<?php\nreturn ['weight' => 5];\n");

        $config = ConfigLoader::load($path);

        $this->assertSame(['weight' => 5], $config);
        unlink($path);
    }

    public function testLoadThrowsWhenFileMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        ConfigLoader::load('/nonexistent/path/config.php');
    }
}
```

- [ ] **Step 11: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Support/ConfigLoaderTest.php`
Expected: FAIL — class not found.

- [ ] **Step 12: Implement `ConfigLoader`**

```php
<?php
// src/Support/ConfigLoader.php
declare(strict_types=1);

namespace AdyaSoft\Security\Support;

final class ConfigLoader
{
    public static function load(string $configPath): array
    {
        if (!is_file($configPath)) {
            throw new \RuntimeException("Config file not found: {$configPath}");
        }

        return require $configPath;
    }
}
```

- [ ] **Step 13: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Support/ConfigLoaderTest.php`
Expected: PASS (2 tests)

- [ ] **Step 14: Write the initial config files (empty/placeholder shape used by later tasks — NFR-7)**

```php
<?php
// config/scoring.php
declare(strict_types=1);

return [
    // signal_name => weight (points added to composite score when signal fires)
    'weights' => [
        'file_new' => 20,
        'file_modified' => 25,
        'file_deleted' => 10,
        'file_in_uploads_is_php' => 40,
        'file_in_mu_plugins_new' => 45,
        'core_file_checksum_mismatch' => 35,
        'core_file_not_in_manifest' => 35,
        'plugin_checksum_mismatch' => 30,
        'entropy_high' => 25,
        'entropy_obfuscation_pattern' => 30,
        'user_not_in_known_good_roster' => 50,
        'user_created_since_last_scan' => 30,
        'page_new' => 15,
        'page_modified' => 10,
        'page_unexpected_author' => 25,
        'htaccess_diff' => 30,
        'htaccess_external_redirect' => 35,
    ],
    // composite score (sum of fired signal weights) => severity band, evaluated high to low
    'severity_thresholds' => [
        'CRITICAL' => 70,
        'HIGH' => 45,
        'MEDIUM' => 20,
        'LOW' => 0,
    ],
];
```

```php
<?php
// config/mail.php
declare(strict_types=1);

return [
    'from' => 'security-scanner@example.com',
    'to' => ['security-ops@example.com'],
    'alert_on_bands' => ['CRITICAL', 'HIGH'],
    'digest_hour_utc' => 6,
];
```

```php
<?php
// config/sites.php
declare(strict_types=1);

// Per-site overrides, keyed by site_id (as recorded in the manifest).
// known_good_users: usernames allowed on the admin/editor roster without alerting.
return [
    // 'site-a' => ['known_good_users' => ['admin', 'editor1']],
];
```

- [ ] **Step 15: Write `.gitignore`**

```
/vendor/
/data/
.phpunit.result.cache
```

- [ ] **Step 16: Write `README.md` explaining the deployment model (per spec A2)**

```markdown
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
```

- [ ] **Step 17: Write the `bin/run.php` stub (full wiring happens in Task 16)**

```php
<?php
// bin/run.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

fwrite(STDERR, "bin/run.php: not yet wired up (see Task 16 of the implementation plan)\n");
exit(1);
```

- [ ] **Step 18: Run the full test suite to confirm the scaffold is green**

Run: `vendor/bin/phpunit`
Expected: PASS (4 tests)

- [ ] **Step 19: Commit**

```bash
git add composer.json composer.lock phpunit.xml src/Autoload/autoload.php \
  src/Support/Logger.php src/Support/ConfigLoader.php config/ bin/run.php \
  .gitignore README.md tests/
git commit -m "chore: scaffold PHP scanner project (autoloader, logger, config loader)"
```

---

### Task 2: Site discovery & manifest

**Files:**
- Create: `src/Discovery/SiteDiscoverer.php`
- Create: `src/Discovery/ManifestStore.php`
- Test: `tests/Discovery/SiteDiscovererTest.php`
- Test: `tests/Discovery/ManifestStoreTest.php`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure filesystem + JSON).
- Produces:
  - `AdyaSoft\Security\Discovery\SiteDiscoverer::__construct(string $accountHomePath, array $excludeDirs = ['security-scanner'])`, method `discover(): array` — returns a list of absolute paths, each a directory containing `wp-config.php` + `wp-content/` + `wp-admin/` + `wp-includes/`.
  - `AdyaSoft\Security\Discovery\ManifestStore::__construct(string $manifestPath)`, methods `load(): array`, `save(array $manifest): void`, `reconcile(array $manifest, array $discoveredPaths): array` — returns an updated manifest: new paths get `{site_id, path, first_seen: now, last_seen: now, status: 'active'}`; previously-known paths found again get `last_seen` bumped and `status: 'active'`; previously-known paths not found this run get `status: 'missing'` (never deleted from the manifest) (FR-2, FR-3). `site_id` is a stable slug derived from the path (e.g. `substr(sha1($path), 0, 12)`).

- [ ] **Step 1: Write the failing test for `SiteDiscoverer`**

```php
<?php
// tests/Discovery/SiteDiscovererTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Discovery;

use AdyaSoft\Security\Discovery\SiteDiscoverer;
use PHPUnit\Framework\TestCase;

final class SiteDiscovererTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/discover-' . uniqid('', true);
        mkdir($this->root, 0700, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    private function makeWpSite(string $path): void
    {
        mkdir($path . '/wp-content', 0700, true);
        mkdir($path . '/wp-admin', 0700, true);
        mkdir($path . '/wp-includes', 0700, true);
        file_put_contents($path . '/wp-config.php', "<?php\n");
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function testDiscoversSingleSiteInPublicHtml(): void
    {
        $this->makeWpSite($this->root . '/public_html');

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([$this->root . '/public_html'], $found);
    }

    public function testDiscoversMultipleAddonDomainSites(): void
    {
        $this->makeWpSite($this->root . '/public_html');
        $this->makeWpSite($this->root . '/domains/other.com/public_html');

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        sort($found);
        $expected = [
            $this->root . '/domains/other.com/public_html',
            $this->root . '/public_html',
        ];
        sort($expected);
        $this->assertSame($expected, $found);
    }

    public function testExcludesTheScannerOwnDirectory(): void
    {
        $this->makeWpSite($this->root . '/public_html');
        mkdir($this->root . '/security-scanner', 0700, true);

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([$this->root . '/public_html'], $found);
    }

    public function testIgnoresDirectoryMissingWpConfig(): void
    {
        mkdir($this->root . '/public_html/wp-content', 0700, true);
        mkdir($this->root . '/public_html/wp-admin', 0700, true);
        mkdir($this->root . '/public_html/wp-includes', 0700, true);
        // no wp-config.php

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([], $found);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Discovery/SiteDiscovererTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `SiteDiscoverer`**

```php
<?php
// src/Discovery/SiteDiscoverer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Discovery;

final class SiteDiscoverer
{
    private const MAX_DEPTH = 6;

    public function __construct(
        private readonly string $accountHomePath,
        private readonly array $excludeDirs = ['security-scanner'],
    ) {
    }

    /** @return string[] absolute paths of discovered WordPress installations */
    public function discover(): array
    {
        $found = [];
        $this->walk(rtrim($this->accountHomePath, '/'), 0, $found);
        sort($found);
        return $found;
    }

    private function walk(string $dir, int $depth, array &$found): void
    {
        if ($depth > self::MAX_DEPTH || !is_dir($dir)) {
            return;
        }

        if ($this->isWordPressInstallation($dir)) {
            $found[] = $dir;
            return; // don't descend into a discovered site's own tree
        }

        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if (in_array($entry, $this->excludeDirs, true)) {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                $this->walk($path, $depth + 1, $found);
            }
        }
    }

    private function isWordPressInstallation(string $dir): bool
    {
        return is_file($dir . '/wp-config.php')
            && is_dir($dir . '/wp-content')
            && is_dir($dir . '/wp-admin')
            && is_dir($dir . '/wp-includes');
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Discovery/SiteDiscovererTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Write the failing test for `ManifestStore`**

```php
<?php
// tests/Discovery/ManifestStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Discovery;

use AdyaSoft\Security\Discovery\ManifestStore;
use PHPUnit\Framework\TestCase;

final class ManifestStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/manifest-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenFileMissing(): void
    {
        $store = new ManifestStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new ManifestStore($this->path);
        $manifest = ['abc123' => ['site_id' => 'abc123', 'path' => '/x', 'status' => 'active']];

        $store->save($manifest);

        $this->assertSame($manifest, $store->load());
    }

    public function testReconcileAddsNewSiteWithFirstSeenAndLastSeen(): void
    {
        $store = new ManifestStore($this->path);
        $updated = $store->reconcile([], ['/home/user/public_html']);

        $siteId = array_key_first($updated);
        $entry = $updated[$siteId];

        $this->assertSame('/home/user/public_html', $entry['path']);
        $this->assertSame('active', $entry['status']);
        $this->assertArrayHasKey('first_seen', $entry);
        $this->assertArrayHasKey('last_seen', $entry);
    }

    public function testReconcileMarksMissingSiteRatherThanDeletingIt(): void
    {
        $store = new ManifestStore($this->path);
        $first = $store->reconcile([], ['/home/user/public_html']);

        $second = $store->reconcile($first, []); // site no longer discovered

        $siteId = array_key_first($second);
        $this->assertArrayHasKey($siteId, $second);
        $this->assertSame('missing', $second[$siteId]['status']);
    }

    public function testReconcileReactivatesAPreviouslyMissingSite(): void
    {
        $store = new ManifestStore($this->path);
        $first = $store->reconcile([], ['/home/user/public_html']);
        $second = $store->reconcile($first, []);

        $third = $store->reconcile($second, ['/home/user/public_html']);

        $siteId = array_key_first($third);
        $this->assertSame('active', $third[$siteId]['status']);
        $this->assertSame($first[$siteId]['first_seen'], $third[$siteId]['first_seen']);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Discovery/ManifestStoreTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `ManifestStore`**

```php
<?php
// src/Discovery/ManifestStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Discovery;

final class ManifestStore
{
    public function __construct(private readonly string $manifestPath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->manifestPath)) {
            return [];
        }
        $contents = file_get_contents($this->manifestPath);
        $decoded = json_decode($contents, true);
        return is_array($decoded) ? $decoded : [];
    }

    public function save(array $manifest): void
    {
        $dir = dirname($this->manifestPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents(
            $this->manifestPath,
            json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
    }

    /**
     * @param array $manifest existing manifest, keyed by site_id
     * @param string[] $discoveredPaths absolute paths found by SiteDiscoverer this run
     */
    public function reconcile(array $manifest, array $discoveredPaths): array
    {
        $now = date('c');
        $byPath = [];
        foreach ($manifest as $siteId => $entry) {
            $byPath[$entry['path']] = $siteId;
        }

        $discoveredSet = array_flip($discoveredPaths);

        foreach ($discoveredPaths as $path) {
            if (isset($byPath[$path])) {
                $siteId = $byPath[$path];
                $manifest[$siteId]['status'] = 'active';
                $manifest[$siteId]['last_seen'] = $now;
            } else {
                $siteId = substr(sha1($path), 0, 12);
                $manifest[$siteId] = [
                    'site_id' => $siteId,
                    'path' => $path,
                    'first_seen' => $now,
                    'last_seen' => $now,
                    'status' => 'active',
                ];
            }
        }

        foreach ($manifest as $siteId => $entry) {
            if (!isset($discoveredSet[$entry['path']])) {
                $manifest[$siteId]['status'] = 'missing';
            }
        }

        return $manifest;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Discovery/ManifestStoreTest.php`
Expected: PASS (5 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Discovery/ tests/Discovery/
git commit -m "feat: add site discovery and manifest reconciliation (FR-1, FR-2, FR-3)"
```

---

### Task 3: wp-config.php credential parser

**Files:**
- Create: `src/WordPress/WpConfigParser.php`
- Test: `tests/WordPress/WpConfigParserTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\WordPress\WpConfigParser::parse(string $wpConfigContents): ?array` — returns `['db_name' => ..., 'db_user' => ..., 'db_password' => ..., 'db_host' => ..., 'table_prefix' => ...]` on success, or `null` if any required field can't be found (caller treats `null` as `needs_manual_config`, per spec A4). Static method, takes file *contents* (not a path) so it never touches the filesystem itself — easy to unit test, and keeps the "never `include` wp-config.php" constraint visible at the call site.

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/WordPress/WpConfigParserTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\WordPress\WpConfigParser;
use PHPUnit\Framework\TestCase;

final class WpConfigParserTest extends TestCase
{
    public function testParsesStandardSingleQuotedWpConfig(): void
    {
        $contents = <<<'PHP'
        <?php
        define( 'DB_NAME', 'wp_mydb' );
        define( 'DB_USER', 'wp_user' );
        define( 'DB_PASSWORD', 'S3cr3t!' );
        define( 'DB_HOST', 'localhost' );
        $table_prefix = 'wp_';
        require_once ABSPATH . 'wp-settings.php';
        PHP;

        $result = WpConfigParser::parse($contents);

        $this->assertSame([
            'db_name' => 'wp_mydb',
            'db_user' => 'wp_user',
            'db_password' => 'S3cr3t!',
            'db_host' => 'localhost',
            'table_prefix' => 'wp_',
        ], $result);
    }

    public function testParsesDoubleQuotedAndCompactSpacing(): void
    {
        $contents = <<<'PHP'
        <?php
        define("DB_NAME","otherdb");
        define("DB_USER","otheruser");
        define("DB_PASSWORD","p@ss");
        define("DB_HOST","127.0.0.1");
        $table_prefix="wp7x_";
        PHP;

        $result = WpConfigParser::parse($contents);

        $this->assertSame('otherdb', $result['db_name']);
        $this->assertSame('wp7x_', $result['table_prefix']);
    }

    public function testReturnsNullWhenDbNameMissing(): void
    {
        $contents = "<?php\ndefine('DB_USER', 'u');\n";
        $this->assertNull(WpConfigParser::parse($contents));
    }

    public function testReturnsNullWhenCredentialsComeFromGetenv(): void
    {
        $contents = "<?php\ndefine('DB_NAME', getenv('DB_NAME'));\n";
        $this->assertNull(WpConfigParser::parse($contents));
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/WordPress/WpConfigParserTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `WpConfigParser`**

```php
<?php
// src/WordPress/WpConfigParser.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class WpConfigParser
{
    public static function parse(string $wpConfigContents): ?array
    {
        $dbName = self::extractDefine($wpConfigContents, 'DB_NAME');
        $dbUser = self::extractDefine($wpConfigContents, 'DB_USER');
        $dbPassword = self::extractDefine($wpConfigContents, 'DB_PASSWORD');
        $dbHost = self::extractDefine($wpConfigContents, 'DB_HOST');
        $tablePrefix = self::extractTablePrefix($wpConfigContents);

        if ($dbName === null || $dbUser === null || $dbPassword === null
            || $dbHost === null || $tablePrefix === null) {
            return null;
        }

        return [
            'db_name' => $dbName,
            'db_user' => $dbUser,
            'db_password' => $dbPassword,
            'db_host' => $dbHost,
            'table_prefix' => $tablePrefix,
        ];
    }

    private static function extractDefine(string $contents, string $constant): ?string
    {
        $pattern = '/define\s*\(\s*[\'"]' . preg_quote($constant, '/')
            . '[\'"]\s*,\s*[\'"]((?:[^\'"\\\\]|\\\\.)*)[\'"]\s*\)/';

        if (preg_match($pattern, $contents, $matches) === 1) {
            return stripslashes($matches[1]);
        }

        return null;
    }

    private static function extractTablePrefix(string $contents): ?string
    {
        $pattern = '/\$table_prefix\s*=\s*[\'"]([a-zA-Z0-9_]*)[\'"]\s*;/';

        if (preg_match($pattern, $contents, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/WordPress/WpConfigParserTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/WordPress/WpConfigParser.php tests/WordPress/WpConfigParserTest.php
git commit -m "feat: add text-based wp-config.php credential parser (spec A4)"
```

---

### Task 4: Database repository layer (SQLite-backed tests, MySQL in prod)

**Files:**
- Create: `src/WordPress/DbConnectionFactory.php`
- Create: `src/WordPress/UserRepository.php`
- Create: `src/WordPress/PageRepository.php`
- Create: `src/WordPress/OptionsRepository.php`
- Test: `tests/WordPress/UserRepositoryTest.php`
- Test: `tests/WordPress/PageRepositoryTest.php`
- Test: `tests/WordPress/OptionsRepositoryTest.php`
- Test: `tests/Fixtures/SqliteWpSchema.php` (shared test helper, not a PHPUnit test itself)

**Interfaces:**
- Produces: `AdyaSoft\Security\WordPress\DbConnectionFactory::createMysql(array $credentials): \PDO` — builds a `PDO` from the array shape returned by `WpConfigParser::parse()` (`db_name`, `db_user`, `db_password`, `db_host`), DSN `mysql:host=...;dbname=...;charset=utf8mb4`, throws on failure.
- Produces: `AdyaSoft\Security\WordPress\UserRepository::__construct(\PDO $pdo, string $tablePrefix)`, method `findAdminAndEditorUsers(): array` — returns list of `['id' => int, 'user_login' => string, 'user_email' => string, 'user_registered' => string (ISO), 'roles' => string[]]` for users whose `{prefix}capabilities` meta unserializes to include `administrator` or `editor`.
- Produces: `AdyaSoft\Security\WordPress\PageRepository::__construct(\PDO $pdo, string $tablePrefix)`, method `findPublishedPages(): array` — returns list of `['id' => int, 'title' => string, 'slug' => string, 'author_login' => string, 'published_at' => string (ISO), 'modified_at' => string (ISO), 'content_hash' => string (sha256 of post_content)]` for `post_type='page' AND post_status='publish'`, joined to the author's `user_login`.
- Produces: `AdyaSoft\Security\WordPress\OptionsRepository::__construct(\PDO $pdo, string $tablePrefix)`, method `getActivePlugins(): array` — returns list of plugin file strings (e.g. `akismet/akismet.php`) unserialized from the `active_plugins` option.
- Consumes (test-only): `tests/Fixtures/SqliteWpSchema.php::createInMemoryDb(): \PDO` — builds an in-memory SQLite DB with `{prefix}users`, `{prefix}usermeta`, `{prefix}posts`, `{prefix}options` tables shaped like WordPress's real schema, for repository tests to run real SQL against (spec A12).

- [ ] **Step 1: Write the shared SQLite fixture helper**

```php
<?php
// tests/Fixtures/SqliteWpSchema.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Fixtures;

final class SqliteWpSchema
{
    public static function createInMemoryDb(string $prefix = 'wp_'): \PDO
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $pdo->exec("CREATE TABLE {$prefix}users (
            ID INTEGER PRIMARY KEY,
            user_login TEXT,
            user_email TEXT,
            user_registered TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}usermeta (
            umeta_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            meta_key TEXT,
            meta_value TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}posts (
            ID INTEGER PRIMARY KEY,
            post_author INTEGER,
            post_title TEXT,
            post_name TEXT,
            post_content TEXT,
            post_status TEXT,
            post_type TEXT,
            post_date TEXT,
            post_modified TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}options (
            option_id INTEGER PRIMARY KEY,
            option_name TEXT,
            option_value TEXT
        )");

        return $pdo;
    }

    public static function insertUser(
        \PDO $pdo,
        string $prefix,
        int $id,
        string $login,
        string $email,
        string $registered,
        array $roles,
    ): void {
        $pdo->prepare("INSERT INTO {$prefix}users (ID, user_login, user_email, user_registered) VALUES (?, ?, ?, ?)")
            ->execute([$id, $login, $email, $registered]);

        $serializedRoles = 'a:' . count($roles) . ':{';
        foreach ($roles as $role) {
            $serializedRoles .= 's:1:"1";s:' . strlen($role) . ':"' . $role . '";';
        }
        $serializedRoles .= '}';

        $pdo->prepare("INSERT INTO {$prefix}usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)")
            ->execute([$id, "{$prefix}capabilities", $serializedRoles]);
    }

    public static function insertPage(
        \PDO $pdo,
        string $prefix,
        int $id,
        int $authorId,
        string $title,
        string $slug,
        string $content,
        string $publishedAt,
        string $modifiedAt,
    ): void {
        $pdo->prepare(
            "INSERT INTO {$prefix}posts (ID, post_author, post_title, post_name, post_content, post_status, post_type, post_date, post_modified)
             VALUES (?, ?, ?, ?, ?, 'publish', 'page', ?, ?)"
        )->execute([$id, $authorId, $title, $slug, $content, $publishedAt, $modifiedAt]);
    }

    public static function setOption(\PDO $pdo, string $prefix, string $name, string $serializedValue): void
    {
        $pdo->prepare("INSERT INTO {$prefix}options (option_name, option_value) VALUES (?, ?)")
            ->execute([$name, $serializedValue]);
    }
}
```

- [ ] **Step 2: Write the failing test for `UserRepository`**

```php
<?php
// tests/WordPress/UserRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\Tests\Fixtures\SqliteWpSchema;
use AdyaSoft\Security\WordPress\UserRepository;
use PHPUnit\Framework\TestCase;

final class UserRepositoryTest extends TestCase
{
    public function testReturnsOnlyAdminAndEditorUsers(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);
        SqliteWpSchema::insertUser($pdo, 'wp_', 2, 'writer', 'writer@example.com', '2024-02-01 00:00:00', ['editor']);
        SqliteWpSchema::insertUser($pdo, 'wp_', 3, 'shopper', 'shopper@example.com', '2024-03-01 00:00:00', ['customer']);

        $repo = new UserRepository($pdo, 'wp_');
        $users = $repo->findAdminAndEditorUsers();

        $logins = array_column($users, 'user_login');
        sort($logins);
        $this->assertSame(['boss', 'writer'], $logins);
    }

    public function testIncludesRolesAndRegistrationDate(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);

        $repo = new UserRepository($pdo, 'wp_');
        $users = $repo->findAdminAndEditorUsers();

        $this->assertSame(['administrator'], $users[0]['roles']);
        $this->assertSame('2024-01-01 00:00:00', $users[0]['user_registered']);
    }
}
```

- [ ] **Step 3: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/WordPress/UserRepositoryTest.php`
Expected: FAIL — class not found.

- [ ] **Step 4: Implement `UserRepository`**

```php
<?php
// src/WordPress/UserRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class UserRepository
{
    private const RELEVANT_ROLES = ['administrator', 'editor'];

    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function findAdminAndEditorUsers(): array
    {
        $stmt = $this->pdo->query(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value
             FROM {$this->tablePrefix}users u
             JOIN {$this->tablePrefix}usermeta m
               ON m.user_id = u.ID AND m.meta_key = '{$this->tablePrefix}capabilities'"
        );

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $roles = $this->rolesFromSerializedCapabilities($row['meta_value']);
            $relevant = array_values(array_intersect($roles, self::RELEVANT_ROLES));
            if ($relevant === []) {
                continue;
            }
            $results[] = [
                'id' => (int) $row['ID'],
                'user_login' => $row['user_login'],
                'user_email' => $row['user_email'],
                'user_registered' => $row['user_registered'],
                'roles' => $relevant,
            ];
        }

        return $results;
    }

    private function rolesFromSerializedCapabilities(string $serialized): array
    {
        $unserialized = @unserialize($serialized, ['allowed_classes' => false]);
        if (!is_array($unserialized)) {
            return [];
        }
        return array_keys(array_filter($unserialized));
    }
}
```

- [ ] **Step 5: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/WordPress/UserRepositoryTest.php`
Expected: PASS (2 tests)

- [ ] **Step 6: Write the failing test for `PageRepository`**

```php
<?php
// tests/WordPress/PageRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\Tests\Fixtures\SqliteWpSchema;
use AdyaSoft\Security\WordPress\PageRepository;
use PHPUnit\Framework\TestCase;

final class PageRepositoryTest extends TestCase
{
    public function testReturnsPublishedPagesWithAuthorLoginAndContentHash(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);
        SqliteWpSchema::insertPage($pdo, 'wp_', 10, 1, 'About', 'about', 'Hello world', '2024-01-05 00:00:00', '2024-01-05 00:00:00');

        $repo = new PageRepository($pdo, 'wp_');
        $pages = $repo->findPublishedPages();

        $this->assertCount(1, $pages);
        $this->assertSame('About', $pages[0]['title']);
        $this->assertSame('about', $pages[0]['slug']);
        $this->assertSame('boss', $pages[0]['author_login']);
        $this->assertSame(hash('sha256', 'Hello world'), $pages[0]['content_hash']);
    }

    public function testExcludesDraftAndNonPagePostTypes(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);
        SqliteWpSchema::insertPage($pdo, 'wp_', 10, 1, 'Draft Page', 'draft', 'x', '2024-01-05 00:00:00', '2024-01-05 00:00:00');
        $pdo->exec("UPDATE wp_posts SET post_status = 'draft' WHERE ID = 10");
        $pdo->exec("INSERT INTO wp_posts (ID, post_author, post_title, post_name, post_content, post_status, post_type, post_date, post_modified)
                     VALUES (11, 1, 'A Post', 'a-post', 'y', 'publish', 'post', '2024-01-06 00:00:00', '2024-01-06 00:00:00')");

        $repo = new PageRepository($pdo, 'wp_');
        $pages = $repo->findPublishedPages();

        $this->assertSame([], $pages);
    }
}
```

- [ ] **Step 7: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/WordPress/PageRepositoryTest.php`
Expected: FAIL — class not found.

- [ ] **Step 8: Implement `PageRepository`**

```php
<?php
// src/WordPress/PageRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class PageRepository
{
    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function findPublishedPages(): array
    {
        $stmt = $this->pdo->query(
            "SELECT p.ID, p.post_title, p.post_name, p.post_content, p.post_date, p.post_modified, u.user_login
             FROM {$this->tablePrefix}posts p
             JOIN {$this->tablePrefix}users u ON u.ID = p.post_author
             WHERE p.post_type = 'page' AND p.post_status = 'publish'"
        );

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $results[] = [
                'id' => (int) $row['ID'],
                'title' => $row['post_title'],
                'slug' => $row['post_name'],
                'author_login' => $row['user_login'],
                'published_at' => $row['post_date'],
                'modified_at' => $row['post_modified'],
                'content_hash' => hash('sha256', $row['post_content']),
            ];
        }

        return $results;
    }
}
```

- [ ] **Step 9: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/WordPress/PageRepositoryTest.php`
Expected: PASS (2 tests)

- [ ] **Step 10: Write the failing test for `OptionsRepository`**

```php
<?php
// tests/WordPress/OptionsRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\Tests\Fixtures\SqliteWpSchema;
use AdyaSoft\Security\WordPress\OptionsRepository;
use PHPUnit\Framework\TestCase;

final class OptionsRepositoryTest extends TestCase
{
    public function testGetActivePluginsUnserializesTheOption(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        $plugins = ['akismet/akismet.php', 'contact-form-7/wp-contact-form-7.php'];
        SqliteWpSchema::setOption($pdo, 'wp_', 'active_plugins', serialize($plugins));

        $repo = new OptionsRepository($pdo, 'wp_');

        $this->assertSame($plugins, $repo->getActivePlugins());
    }

    public function testGetActivePluginsReturnsEmptyArrayWhenOptionMissing(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();

        $repo = new OptionsRepository($pdo, 'wp_');

        $this->assertSame([], $repo->getActivePlugins());
    }
}
```

- [ ] **Step 11: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/WordPress/OptionsRepositoryTest.php`
Expected: FAIL — class not found.

- [ ] **Step 12: Implement `OptionsRepository`**

```php
<?php
// src/WordPress/OptionsRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class OptionsRepository
{
    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function getActivePlugins(): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT option_value FROM {$this->tablePrefix}options WHERE option_name = 'active_plugins' LIMIT 1"
        );
        $stmt->execute();
        $value = $stmt->fetchColumn();

        if ($value === false) {
            return [];
        }

        $unserialized = @unserialize($value, ['allowed_classes' => false]);
        return is_array($unserialized) ? $unserialized : [];
    }
}
```

- [ ] **Step 13: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/WordPress/OptionsRepositoryTest.php`
Expected: PASS (2 tests)

- [ ] **Step 14: Implement `DbConnectionFactory` (no test — thin PDO-construction wrapper, exercised in Task 16's smoke test via SQLite substitution)**

```php
<?php
// src/WordPress/DbConnectionFactory.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class DbConnectionFactory
{
    public static function createMysql(array $credentials): \PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            $credentials['db_host'],
            $credentials['db_name'],
        );

        return new \PDO($dsn, $credentials['db_user'], $credentials['db_password'], [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_TIMEOUT => 5,
        ]);
    }
}
```

- [ ] **Step 15: Run the full suite**

Run: `vendor/bin/phpunit`
Expected: PASS (all tests so far)

- [ ] **Step 16: Commit**

```bash
git add src/WordPress/ tests/WordPress/ tests/Fixtures/
git commit -m "feat: add DB repository layer for users, pages, active plugins (SQLite-tested)"
```

---

### Task 5: User roster baseline & detector (FR-16, FR-17, FR-18)

**Files:**
- Create: `src/Baseline/UserBaselineStore.php`
- Create: `src/Detectors/UserDetector.php`
- Test: `tests/Baseline/UserBaselineStoreTest.php`
- Test: `tests/Detectors/UserDetectorTest.php`

**Interfaces:**
- Consumes: `UserRepository::findAdminAndEditorUsers()` shape from Task 4 (`id, user_login, user_email, user_registered, roles`).
- Produces: `AdyaSoft\Security\Baseline\UserBaselineStore::__construct(string $baselinePath)`, `load(): array` (returns `[]` if missing), `save(array $users): void` — persists the current roster as the new "last confirmed scan" snapshot (list of `user_login` => `user_registered` at minimum).
- Produces: `AdyaSoft\Security\Detectors\UserDetector::__construct(array $knownGoodUsernames)`, method `detect(array $currentUsers, array $previousScanUsers): array` — returns a list of findings, each `['type' => 'user_not_in_known_good_roster'|'user_created_since_last_scan', 'user_login' => ..., 'details' => [...]]`. `$currentUsers`/`$previousScanUsers` use the `UserRepository` row shape. FR-17: any current user whose `user_login` is not in `$knownGoodUsernames` → `user_not_in_known_good_roster`. FR-18: any current user whose `user_login` was not present in `$previousScanUsers` → `user_created_since_last_scan`, **regardless of** whether they're in the known-good list (a compromised known account creating a new one must still fire this signal, even if that new login happens to already be in the static known-good config — matches FR-18's explicit "regardless of whether they're on the known-good list").

- [ ] **Step 1: Write the failing test for `UserBaselineStore`**

```php
<?php
// tests/Baseline/UserBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\UserBaselineStore;
use PHPUnit\Framework\TestCase;

final class UserBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/user-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new UserBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new UserBaselineStore($this->path);
        $users = [['id' => 1, 'user_login' => 'boss', 'user_email' => 'boss@example.com', 'user_registered' => '2024-01-01', 'roles' => ['administrator']]];

        $store->save($users);

        $this->assertSame($users, $store->load());
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Baseline/UserBaselineStoreTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `UserBaselineStore`**

```php
<?php
// src/Baseline/UserBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class UserBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $decoded = json_decode(file_get_contents($this->baselinePath), true);
        return is_array($decoded) ? $decoded : [];
    }

    public function save(array $users): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Baseline/UserBaselineStoreTest.php`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the failing test for `UserDetector`**

```php
<?php
// tests/Detectors/UserDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\UserDetector;
use PHPUnit\Framework\TestCase;

final class UserDetectorTest extends TestCase
{
    private function user(string $login): array
    {
        return ['id' => 1, 'user_login' => $login, 'user_email' => "{$login}@example.com", 'user_registered' => '2024-01-01', 'roles' => ['administrator']];
    }

    public function testFlagsUserNotInKnownGoodRoster(): void
    {
        $detector = new UserDetector(['boss']);

        $findings = $detector->detect([$this->user('boss'), $this->user('rogue')], [$this->user('boss'), $this->user('rogue')]);

        $types = array_column($findings, 'type');
        $this->assertContains('user_not_in_known_good_roster', $types);
        $rogueFinding = array_values(array_filter($findings, fn ($f) => $f['user_login'] === 'rogue'))[0];
        $this->assertSame('user_not_in_known_good_roster', $rogueFinding['type']);
    }

    public function testFlagsUserCreatedSincePreviousScanEvenIfKnownGood(): void
    {
        $detector = new UserDetector(['boss', 'newadmin']);

        $findings = $detector->detect(
            [$this->user('boss'), $this->user('newadmin')],
            [$this->user('boss')], // newadmin wasn't present last scan
        );

        $newAdminFindings = array_column(
            array_filter($findings, fn ($f) => $f['user_login'] === 'newadmin'),
            'type'
        );
        $this->assertContains('user_created_since_last_scan', $newAdminFindings);
        $this->assertNotContains('user_not_in_known_good_roster', $newAdminFindings);
    }

    public function testNoFindingsForKnownExistingUser(): void
    {
        $detector = new UserDetector(['boss']);

        $findings = $detector->detect([$this->user('boss')], [$this->user('boss')]);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/UserDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `UserDetector`**

```php
<?php
// src/Detectors/UserDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class UserDetector
{
    public function __construct(private readonly array $knownGoodUsernames)
    {
    }

    public function detect(array $currentUsers, array $previousScanUsers): array
    {
        $previousLogins = array_column($previousScanUsers, 'user_login');
        $findings = [];

        foreach ($currentUsers as $user) {
            if (!in_array($user['user_login'], $this->knownGoodUsernames, true)) {
                $findings[] = [
                    'type' => 'user_not_in_known_good_roster',
                    'user_login' => $user['user_login'],
                    'details' => $user,
                ];
            }

            if (!in_array($user['user_login'], $previousLogins, true)) {
                $findings[] = [
                    'type' => 'user_created_since_last_scan',
                    'user_login' => $user['user_login'],
                    'details' => $user,
                ];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/UserDetectorTest.php`
Expected: PASS (3 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Baseline/UserBaselineStore.php src/Detectors/UserDetector.php tests/Baseline/UserBaselineStoreTest.php tests/Detectors/UserDetectorTest.php
git commit -m "feat: add user roster baseline and detector (FR-16, FR-17, FR-18)"
```

---

### Task 6: Page/post baseline & detector (FR-20, FR-21, FR-22)

**Files:**
- Create: `src/Baseline/PageBaselineStore.php`
- Create: `src/Detectors/PageDetector.php`
- Test: `tests/Baseline/PageBaselineStoreTest.php`
- Test: `tests/Detectors/PageDetectorTest.php`

**Interfaces:**
- Consumes: `PageRepository::findPublishedPages()` shape from Task 4 (`id, title, slug, author_login, published_at, modified_at, content_hash`).
- Produces: `AdyaSoft\Security\Baseline\PageBaselineStore` — same `load()`/`save()` shape as `UserBaselineStore` (Task 5), storing the page list.
- Produces: `AdyaSoft\Security\Detectors\PageDetector::__construct(array $knownContributorLogins)`, method `detect(array $currentPages, array $baselinePages): array` — findings of type `page_new` (id not in baseline), `page_modified` (id in baseline but `content_hash` differs), and `page_unexpected_author` (author_login not in `$knownContributorLogins`, additive to `page_new`/`page_modified` — a page can carry both findings).

- [ ] **Step 1: Write the failing test for `PageBaselineStore`**

```php
<?php
// tests/Baseline/PageBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\PageBaselineStore;
use PHPUnit\Framework\TestCase;

final class PageBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/page-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new PageBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new PageBaselineStore($this->path);
        $pages = [['id' => 10, 'title' => 'About', 'slug' => 'about', 'author_login' => 'boss', 'published_at' => '2024-01-01', 'modified_at' => '2024-01-01', 'content_hash' => 'abc']];

        $store->save($pages);

        $this->assertSame($pages, $store->load());
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Baseline/PageBaselineStoreTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `PageBaselineStore`**

```php
<?php
// src/Baseline/PageBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class PageBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $decoded = json_decode(file_get_contents($this->baselinePath), true);
        return is_array($decoded) ? $decoded : [];
    }

    public function save(array $pages): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, json_encode($pages, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Baseline/PageBaselineStoreTest.php`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the failing test for `PageDetector`**

```php
<?php
// tests/Detectors/PageDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\PageDetector;
use PHPUnit\Framework\TestCase;

final class PageDetectorTest extends TestCase
{
    private function page(int $id, string $login, string $hash): array
    {
        return ['id' => $id, 'title' => "Page {$id}", 'slug' => "page-{$id}", 'author_login' => $login, 'published_at' => '2024-01-01', 'modified_at' => '2024-01-01', 'content_hash' => $hash];
    }

    public function testFlagsNewPage(): void
    {
        $detector = new PageDetector(['boss']);

        $findings = $detector->detect([$this->page(1, 'boss', 'hash1')], []);

        $this->assertSame('page_new', $findings[0]['type']);
        $this->assertSame(1, $findings[0]['page_id']);
    }

    public function testFlagsModifiedPageWhenContentHashDiffers(): void
    {
        $detector = new PageDetector(['boss']);
        $baseline = [$this->page(1, 'boss', 'hash-old')];
        $current = [$this->page(1, 'boss', 'hash-new')];

        $findings = $detector->detect($current, $baseline);

        $this->assertSame('page_modified', $findings[0]['type']);
    }

    public function testFlagsUnexpectedAuthorAdditively(): void
    {
        $detector = new PageDetector(['boss']);

        $findings = $detector->detect([$this->page(1, 'attacker', 'hash1')], []);

        $types = array_column($findings, 'type');
        $this->assertContains('page_new', $types);
        $this->assertContains('page_unexpected_author', $types);
    }

    public function testNoFindingsForUnchangedKnownPage(): void
    {
        $detector = new PageDetector(['boss']);
        $page = $this->page(1, 'boss', 'hash1');

        $findings = $detector->detect([$page], [$page]);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/PageDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `PageDetector`**

```php
<?php
// src/Detectors/PageDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class PageDetector
{
    public function __construct(private readonly array $knownContributorLogins)
    {
    }

    public function detect(array $currentPages, array $baselinePages): array
    {
        $baselineById = [];
        foreach ($baselinePages as $page) {
            $baselineById[$page['id']] = $page;
        }

        $findings = [];

        foreach ($currentPages as $page) {
            $baseline = $baselineById[$page['id']] ?? null;

            if ($baseline === null) {
                $findings[] = ['type' => 'page_new', 'page_id' => $page['id'], 'details' => $page];
            } elseif ($baseline['content_hash'] !== $page['content_hash']) {
                $findings[] = ['type' => 'page_modified', 'page_id' => $page['id'], 'details' => $page];
            }

            if (!in_array($page['author_login'], $this->knownContributorLogins, true)) {
                $findings[] = ['type' => 'page_unexpected_author', 'page_id' => $page['id'], 'details' => $page];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/PageDetectorTest.php`
Expected: PASS (4 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Baseline/PageBaselineStore.php src/Detectors/PageDetector.php tests/Baseline/PageBaselineStoreTest.php tests/Detectors/PageDetectorTest.php
git commit -m "feat: add page baseline and detector (FR-20, FR-21, FR-22)"
```

---

### Task 7: `.htaccess` baseline & detector (FR-25, FR-26)

**Files:**
- Create: `src/Baseline/HtaccessBaselineStore.php`
- Create: `src/Detectors/HtaccessDetector.php`
- Test: `tests/Baseline/HtaccessBaselineStoreTest.php`
- Test: `tests/Detectors/HtaccessDetectorTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\Baseline\HtaccessBaselineStore::__construct(string $baselinePath)`, `load(): ?string` (raw file contents, `null` if no baseline yet), `save(string $contents): void`.
- Produces: `AdyaSoft\Security\Detectors\HtaccessDetector::__construct(array $siteDomains)`, method `detect(?string $currentContents, ?string $baselineContents): array` — findings:
  - `htaccess_diff` (once, `details => ['baseline' => ..., 'current' => ...]`) when `$currentContents !== $baselineContents` and both are non-null, or when one is null and the other isn't (file appeared/disappeared).
  - `htaccess_external_redirect` (one per offending rule) for each `RewriteRule`/`Redirect`/`RedirectMatch` line in `$currentContents` whose target is an absolute URL (`http://`/`https://`) whose host is not in `$siteDomains`.

- [ ] **Step 1: Write the failing test for `HtaccessBaselineStore`**

```php
<?php
// tests/Baseline/HtaccessBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\HtaccessBaselineStore;
use PHPUnit\Framework\TestCase;

final class HtaccessBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/htaccess-baseline-' . uniqid('', true) . '.txt';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsNullWhenNoBaselineYet(): void
    {
        $store = new HtaccessBaselineStore($this->path);
        $this->assertNull($store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new HtaccessBaselineStore($this->path);
        $store->save("RewriteEngine On\n");

        $this->assertSame("RewriteEngine On\n", $store->load());
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Baseline/HtaccessBaselineStoreTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `HtaccessBaselineStore`**

```php
<?php
// src/Baseline/HtaccessBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class HtaccessBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): ?string
    {
        if (!is_file($this->baselinePath)) {
            return null;
        }
        return file_get_contents($this->baselinePath);
    }

    public function save(string $contents): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, $contents);
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Baseline/HtaccessBaselineStoreTest.php`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the failing test for `HtaccessDetector`**

```php
<?php
// tests/Detectors/HtaccessDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\HtaccessDetector;
use PHPUnit\Framework\TestCase;

final class HtaccessDetectorTest extends TestCase
{
    public function testNoFindingsWhenContentsUnchanged(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "RewriteEngine On\n";

        $findings = $detector->detect($contents, $contents);

        $this->assertSame([], $findings);
    }

    public function testFlagsDiffWhenContentsChange(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);

        $findings = $detector->detect("RewriteEngine On\nNewLine\n", "RewriteEngine On\n");

        $this->assertSame('htaccess_diff', $findings[0]['type']);
    }

    public function testFlagsExternalRedirectToUnknownDomain(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "RewriteRule ^bad$ http://evil-spam.example/landing [R=301,L]\n";

        $findings = $detector->detect($contents, $contents);

        $types = array_column($findings, 'type');
        $this->assertContains('htaccess_external_redirect', $types);
        $external = array_values(array_filter($findings, fn ($f) => $f['type'] === 'htaccess_external_redirect'))[0];
        $this->assertStringContainsString('evil-spam.example', $external['details']['target']);
    }

    public function testDoesNotFlagRedirectToKnownSiteDomain(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "Redirect 301 /old https://mysite.com/new\n";

        $findings = $detector->detect($contents, $contents);

        $this->assertSame([], $findings);
    }

    public function testFlagsDiffWhenFileAppearsFromNoBaseline(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);

        $findings = $detector->detect("RewriteEngine On\n", null);

        $this->assertSame('htaccess_diff', $findings[0]['type']);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/HtaccessDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `HtaccessDetector`**

```php
<?php
// src/Detectors/HtaccessDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class HtaccessDetector
{
    public function __construct(private readonly array $siteDomains)
    {
    }

    public function detect(?string $currentContents, ?string $baselineContents): array
    {
        $findings = [];

        if ($currentContents !== $baselineContents) {
            $findings[] = [
                'type' => 'htaccess_diff',
                'details' => ['baseline' => $baselineContents, 'current' => $currentContents],
            ];
        }

        if ($currentContents !== null) {
            foreach ($this->findExternalRedirectTargets($currentContents) as $target) {
                $findings[] = [
                    'type' => 'htaccess_external_redirect',
                    'details' => ['target' => $target],
                ];
            }
        }

        return $findings;
    }

    private function findExternalRedirectTargets(string $contents): array
    {
        $targets = [];
        $lines = preg_split('/\r\n|\r|\n/', $contents);

        foreach ($lines as $line) {
            if (preg_match('/^\s*(?:RewriteRule|RedirectMatch|Redirect)\s+\S+\s+(https?:\/\/\S+)/i', $line, $matches) === 1) {
                $target = $matches[1];
                $host = parse_url($target, PHP_URL_HOST);
                if ($host !== null && !in_array($host, $this->siteDomains, true)) {
                    $targets[] = $target;
                }
            }
        }

        return $targets;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/HtaccessDetectorTest.php`
Expected: PASS (5 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Baseline/HtaccessBaselineStore.php src/Detectors/HtaccessDetector.php tests/Baseline/HtaccessBaselineStoreTest.php tests/Detectors/HtaccessDetectorTest.php
git commit -m "feat: add .htaccess baseline and detector (FR-25, FR-26)"
```

---

### Task 8: File baseline capture & diff detector (FR-4, FR-5)

**Files:**
- Create: `src/Baseline/FileBaselineStore.php`
- Create: `src/Baseline/FileScanner.php`
- Create: `src/Detectors/FileDetector.php`
- Test: `tests/Baseline/FileScannerTest.php`
- Test: `tests/Baseline/FileBaselineStoreTest.php`
- Test: `tests/Detectors/FileDetectorTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\Baseline\FileScanner::__construct(string $siteRootPath)`, method `scan(): array` — walks the entire site tree and returns `[relativePath => ['sha256' => ..., 'size' => int, 'mtime' => int, 'permissions' => string (octal, e.g. "0644")]]` (FR-4's captured attributes). Skips nothing by default (baseline capture is meant to cover everything at a confirmed-clean point).
- Produces: `AdyaSoft\Security\Baseline\FileBaselineStore::__construct(string $baselinePath)` — same `load(): array` / `save(array $entries): void` shape as prior baseline stores.
- Produces: `AdyaSoft\Security\Detectors\FileDetector::__construct()`, method `detect(array $currentScan, array $baseline): array` — findings `file_new` (path in current, not baseline), `file_modified` (path in both, `sha256`/`size`/`mtime`/`permissions` differ), `file_deleted` (path in baseline, not current). Each finding: `['type' => ..., 'path' => ..., 'details' => [...]]`.

- [ ] **Step 1: Write the failing test for `FileScanner`**

```php
<?php
// tests/Baseline/FileScannerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\FileScanner;
use PHPUnit\Framework\TestCase;

final class FileScannerTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/filescan-' . uniqid('', true);
        mkdir($this->root . '/wp-content', 0700, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function testScanReturnsHashSizeMtimeAndPermissionsForEachFile(): void
    {
        file_put_contents($this->root . '/wp-content/index.php', '<?php // silence');

        $scanner = new FileScanner($this->root);
        $result = $scanner->scan();

        $this->assertArrayHasKey('wp-content/index.php', $result);
        $entry = $result['wp-content/index.php'];
        $this->assertSame(hash_file('sha256', $this->root . '/wp-content/index.php'), $entry['sha256']);
        $this->assertSame(filesize($this->root . '/wp-content/index.php'), $entry['size']);
        $this->assertArrayHasKey('mtime', $entry);
        $this->assertArrayHasKey('permissions', $entry);
    }

    public function testScanUsesForwardSlashRelativePathsAcrossNestedDirs(): void
    {
        mkdir($this->root . '/wp-content/uploads/2024', 0700, true);
        file_put_contents($this->root . '/wp-content/uploads/2024/photo.jpg', 'data');

        $scanner = new FileScanner($this->root);
        $result = $scanner->scan();

        $this->assertArrayHasKey('wp-content/uploads/2024/photo.jpg', $result);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Baseline/FileScannerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `FileScanner`**

```php
<?php
// src/Baseline/FileScanner.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class FileScanner
{
    public function __construct(private readonly string $siteRootPath)
    {
    }

    public function scan(): array
    {
        $root = rtrim($this->siteRootPath, '/');
        $results = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY,
        );

        foreach ($iterator as $fileInfo) {
            /** @var \SplFileInfo $fileInfo */
            if (!$fileInfo->isFile()) {
                continue;
            }
            $absolutePath = $fileInfo->getPathname();
            $relativePath = ltrim(substr($absolutePath, strlen($root)), '/');

            $results[$relativePath] = [
                'sha256' => hash_file('sha256', $absolutePath),
                'size' => $fileInfo->getSize(),
                'mtime' => $fileInfo->getMTime(),
                'permissions' => substr(sprintf('%o', $fileInfo->getPerms()), -4),
            ];
        }

        return $results;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Baseline/FileScannerTest.php`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the failing test for `FileBaselineStore`**

```php
<?php
// tests/Baseline/FileBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\FileBaselineStore;
use PHPUnit\Framework\TestCase;

final class FileBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/file-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new FileBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new FileBaselineStore($this->path);
        $entries = ['wp-content/index.php' => ['sha256' => 'abc', 'size' => 10, 'mtime' => 123, 'permissions' => '0644']];

        $store->save($entries);

        $this->assertSame($entries, $store->load());
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Baseline/FileBaselineStoreTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `FileBaselineStore`**

```php
<?php
// src/Baseline/FileBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class FileBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $decoded = json_decode(file_get_contents($this->baselinePath), true);
        return is_array($decoded) ? $decoded : [];
    }

    public function save(array $entries): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Baseline/FileBaselineStoreTest.php`
Expected: PASS (2 tests)

- [ ] **Step 9: Write the failing test for `FileDetector`**

```php
<?php
// tests/Detectors/FileDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\FileDetector;
use PHPUnit\Framework\TestCase;

final class FileDetectorTest extends TestCase
{
    private function entry(string $sha = 'abc', int $size = 10, int $mtime = 100, string $perms = '0644'): array
    {
        return ['sha256' => $sha, 'size' => $size, 'mtime' => $mtime, 'permissions' => $perms];
    }

    public function testFlagsNewFile(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(['shell.php' => $this->entry()], []);

        $this->assertSame('file_new', $findings[0]['type']);
        $this->assertSame('shell.php', $findings[0]['path']);
    }

    public function testFlagsModifiedFileWhenHashDiffers(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(
            ['index.php' => $this->entry('newhash')],
            ['index.php' => $this->entry('oldhash')],
        );

        $this->assertSame('file_modified', $findings[0]['type']);
    }

    public function testFlagsDeletedFile(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect([], ['index.php' => $this->entry()]);

        $this->assertSame('file_deleted', $findings[0]['type']);
    }

    public function testNoFindingsForUnchangedFile(): void
    {
        $detector = new FileDetector();
        $entry = $this->entry();

        $findings = $detector->detect(['index.php' => $entry], ['index.php' => $entry]);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 10: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/FileDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 11: Implement `FileDetector`**

```php
<?php
// src/Detectors/FileDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class FileDetector
{
    public function detect(array $currentScan, array $baseline): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!isset($baseline[$path])) {
                $findings[] = ['type' => 'file_new', 'path' => $path, 'details' => $entry];
            } elseif ($baseline[$path] !== $entry) {
                $findings[] = ['type' => 'file_modified', 'path' => $path, 'details' => ['before' => $baseline[$path], 'after' => $entry]];
            }
        }

        foreach ($baseline as $path => $entry) {
            if (!isset($currentScan[$path])) {
                $findings[] = ['type' => 'file_deleted', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 12: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/FileDetectorTest.php`
Expected: PASS (4 tests)

- [ ] **Step 13: Commit**

```bash
git add src/Baseline/FileScanner.php src/Baseline/FileBaselineStore.php src/Detectors/FileDetector.php tests/Baseline/FileScannerTest.php tests/Baseline/FileBaselineStoreTest.php tests/Detectors/FileDetectorTest.php
git commit -m "feat: add file baseline capture and diff detector (FR-4, FR-5)"
```

---

### Task 9: Uploads-PHP & mu-plugins signals (FR-6, FR-10)

**Files:**
- Create: `src/Detectors/UploadsPhpDetector.php`
- Create: `src/Detectors/MuPluginsDetector.php`
- Test: `tests/Detectors/UploadsPhpDetectorTest.php`
- Test: `tests/Detectors/MuPluginsDetectorTest.php`

**Interfaces:**
- Consumes: the same `$currentScan` shape as `FileDetector` (`relativePath => [...]`), from Task 8.
- Produces: `AdyaSoft\Security\Detectors\UploadsPhpDetector`, method `detect(array $currentScan): array` — finding `file_in_uploads_is_php` for every relative path under `wp-content/uploads/` whose extension is `php`, `phtml`, `php3`, `php4`, `php5`, `php7`, or `phar` (case-insensitive).
- Produces: `AdyaSoft\Security\Detectors\MuPluginsDetector`, method `detect(array $currentScan, array $baseline): array` — finding `file_in_mu_plugins_new` for every relative path under `wp-content/mu-plugins/` present in `$currentScan` but not in `$baseline` (any extension — mu-plugins execute regardless of file type as long as PHP loads them, but a genuinely new file appearing there at all is the signal per FR-10).

- [ ] **Step 1: Write the failing test for `UploadsPhpDetector`**

```php
<?php
// tests/Detectors/UploadsPhpDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\UploadsPhpDetector;
use PHPUnit\Framework\TestCase;

final class UploadsPhpDetectorTest extends TestCase
{
    private function entry(): array
    {
        return ['sha256' => 'x', 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsPhpFileUnderUploads(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect(['wp-content/uploads/2024/shell.php' => $this->entry()]);

        $this->assertSame('file_in_uploads_is_php', $findings[0]['type']);
        $this->assertSame('wp-content/uploads/2024/shell.php', $findings[0]['path']);
    }

    public function testFlagsCaseInsensitiveAndAlternateExtensions(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect([
            'wp-content/uploads/a.PHP' => $this->entry(),
            'wp-content/uploads/b.phtml' => $this->entry(),
        ]);

        $this->assertCount(2, $findings);
    }

    public function testDoesNotFlagNonPhpFilesOrFilesOutsideUploads(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect([
            'wp-content/uploads/2024/photo.jpg' => $this->entry(),
            'wp-content/plugins/some-plugin/handler.php' => $this->entry(),
        ]);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/UploadsPhpDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `UploadsPhpDetector`**

```php
<?php
// src/Detectors/UploadsPhpDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class UploadsPhpDetector
{
    private const PHP_EXTENSIONS = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar'];

    public function detect(array $currentScan): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-content/uploads/')) {
                continue;
            }
            $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (in_array($extension, self::PHP_EXTENSIONS, true)) {
                $findings[] = ['type' => 'file_in_uploads_is_php', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/UploadsPhpDetectorTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Write the failing test for `MuPluginsDetector`**

```php
<?php
// tests/Detectors/MuPluginsDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\MuPluginsDetector;
use PHPUnit\Framework\TestCase;

final class MuPluginsDetectorTest extends TestCase
{
    private function entry(): array
    {
        return ['sha256' => 'x', 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsNewFileInMuPlugins(): void
    {
        $detector = new MuPluginsDetector();

        $findings = $detector->detect(['wp-content/mu-plugins/backdoor.php' => $this->entry()], []);

        $this->assertSame('file_in_mu_plugins_new', $findings[0]['type']);
    }

    public function testDoesNotFlagExistingBaselinedMuPlugin(): void
    {
        $detector = new MuPluginsDetector();
        $entry = $this->entry();

        $findings = $detector->detect(
            ['wp-content/mu-plugins/legit.php' => $entry],
            ['wp-content/mu-plugins/legit.php' => $entry],
        );

        $this->assertSame([], $findings);
    }

    public function testDoesNotFlagFilesOutsideMuPlugins(): void
    {
        $detector = new MuPluginsDetector();

        $findings = $detector->detect(['wp-content/plugins/foo/bar.php' => $this->entry()], []);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/MuPluginsDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `MuPluginsDetector`**

```php
<?php
// src/Detectors/MuPluginsDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class MuPluginsDetector
{
    public function detect(array $currentScan, array $baseline): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-content/mu-plugins/')) {
                continue;
            }
            if (!isset($baseline[$path])) {
                $findings[] = ['type' => 'file_in_mu_plugins_new', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/MuPluginsDetectorTest.php`
Expected: PASS (3 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Detectors/UploadsPhpDetector.php src/Detectors/MuPluginsDetector.php tests/Detectors/UploadsPhpDetectorTest.php tests/Detectors/MuPluginsDetectorTest.php
git commit -m "feat: add uploads-PHP and new-mu-plugin signals (FR-6, FR-10)"
```

---

### Task 10: WordPress.org checksum client + core integrity detector (FR-7, FR-12)

**Files:**
- Create: `src/WordPress/ChecksumClient.php`
- Create: `src/Detectors/CoreIntegrityDetector.php`
- Test: `tests/WordPress/ChecksumClientTest.php`
- Test: `tests/Detectors/CoreIntegrityDetectorTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\WordPress\ChecksumClient::__construct(callable $httpGetJson)` — `$httpGetJson` has signature `(string $url): ?array` (returns decoded JSON body, or `null` on failure), injected so tests never make real HTTP calls. Method `getCoreChecksums(string $version, string $locale = 'en_US'): ?array` — calls `https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}` via the injected callable and returns the `{relative_path: sha256}` map from the response's `checksums` key, or `null` if the call failed/shape was unexpected.
- Produces: `AdyaSoft\Security\Detectors\CoreIntegrityDetector`, method `detect(array $currentScan, array $officialChecksums): array` — for every path in `$currentScan` starting with `wp-admin/` or `wp-includes/`: if not present in `$officialChecksums` → `core_file_not_in_manifest` (FR-7); if present but `sha256` differs → `core_file_checksum_mismatch` (FR-12). A production wiring detail (not tested here, handled in Task 16): the caller is responsible for fetching `officialChecksums` via `ChecksumClient` first and skipping this detector entirely (logging a warning) if the fetch failed — never treating "checksums unavailable" as "every core file is a finding."

- [ ] **Step 1: Write the failing test for `ChecksumClient`**

```php
<?php
// tests/WordPress/ChecksumClientTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\WordPress\ChecksumClient;
use PHPUnit\Framework\TestCase;

final class ChecksumClientTest extends TestCase
{
    public function testGetCoreChecksumsReturnsMapFromResponse(): void
    {
        $capturedUrl = null;
        $client = new ChecksumClient(function (string $url) use (&$capturedUrl): array {
            $capturedUrl = $url;
            return ['checksums' => ['wp-admin/index.php' => 'abc123']];
        });

        $result = $client->getCoreChecksums('6.5.2');

        $this->assertSame(['wp-admin/index.php' => 'abc123'], $result);
        $this->assertStringContainsString('version=6.5.2', $capturedUrl);
    }

    public function testGetCoreChecksumsReturnsNullWhenHttpCallFails(): void
    {
        $client = new ChecksumClient(fn (string $url): ?array => null);

        $this->assertNull($client->getCoreChecksums('6.5.2'));
    }

    public function testGetCoreChecksumsReturnsNullWhenShapeIsUnexpected(): void
    {
        $client = new ChecksumClient(fn (string $url): array => ['unexpected' => true]);

        $this->assertNull($client->getCoreChecksums('6.5.2'));
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/WordPress/ChecksumClientTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `ChecksumClient`**

```php
<?php
// src/WordPress/ChecksumClient.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class ChecksumClient
{
    /** @param callable(string): ?array $httpGetJson */
    public function __construct(private readonly mixed $httpGetJson)
    {
    }

    public function getCoreChecksums(string $version, string $locale = 'en_US'): ?array
    {
        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            urlencode($version),
            urlencode($locale),
        );

        $response = ($this->httpGetJson)($url);

        if (!is_array($response) || !isset($response['checksums']) || !is_array($response['checksums'])) {
            return null;
        }

        return $response['checksums'];
    }

    public function getPluginChecksums(string $slug, string $version): ?array
    {
        $url = sprintf(
            'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
            urlencode($slug),
            urlencode($version),
        );

        $response = ($this->httpGetJson)($url);

        if (!is_array($response) || !isset($response['files']) || !is_array($response['files'])) {
            return null;
        }

        $checksums = [];
        foreach ($response['files'] as $relativePath => $meta) {
            if (is_array($meta) && isset($meta['sha256'])) {
                $checksums[$relativePath] = $meta['sha256'];
            }
        }

        return $checksums;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/WordPress/ChecksumClientTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Write the failing test for `CoreIntegrityDetector`**

```php
<?php
// tests/Detectors/CoreIntegrityDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\CoreIntegrityDetector;
use PHPUnit\Framework\TestCase;

final class CoreIntegrityDetectorTest extends TestCase
{
    private function entry(string $sha): array
    {
        return ['sha256' => $sha, 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsCoreFileNotInOfficialManifest(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-admin/backdoor.php' => $this->entry('x')],
            ['wp-admin/index.php' => 'abc123'],
        );

        $this->assertSame('core_file_not_in_manifest', $findings[0]['type']);
        $this->assertSame('wp-admin/backdoor.php', $findings[0]['path']);
    }

    public function testFlagsChecksumMismatchForKnownCoreFile(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-admin/index.php' => $this->entry('modified-hash')],
            ['wp-admin/index.php' => 'original-hash'],
        );

        $this->assertSame('core_file_checksum_mismatch', $findings[0]['type']);
    }

    public function testIgnoresFilesOutsideCoreDirectories(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/foo.php' => $this->entry('x')],
            [],
        );

        $this->assertSame([], $findings);
    }

    public function testNoFindingsWhenHashMatchesManifest(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-includes/version.php' => $this->entry('matching-hash')],
            ['wp-includes/version.php' => 'matching-hash'],
        );

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/CoreIntegrityDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `CoreIntegrityDetector`**

```php
<?php
// src/Detectors/CoreIntegrityDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class CoreIntegrityDetector
{
    public function detect(array $currentScan, array $officialChecksums): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-admin/') && !str_starts_with($path, 'wp-includes/')) {
                continue;
            }

            if (!isset($officialChecksums[$path])) {
                $findings[] = ['type' => 'core_file_not_in_manifest', 'path' => $path, 'details' => $entry];
            } elseif ($officialChecksums[$path] !== $entry['sha256']) {
                $findings[] = [
                    'type' => 'core_file_checksum_mismatch',
                    'path' => $path,
                    'details' => ['expected' => $officialChecksums[$path], 'actual' => $entry['sha256']],
                ];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/CoreIntegrityDetectorTest.php`
Expected: PASS (4 tests)

- [ ] **Step 9: Commit**

```bash
git add src/WordPress/ChecksumClient.php src/Detectors/CoreIntegrityDetector.php tests/WordPress/ChecksumClientTest.php tests/Detectors/CoreIntegrityDetectorTest.php
git commit -m "feat: add WordPress.org checksum client and core integrity detector (FR-7, FR-12)"
```

---

### Task 11: Plugin checksum integrity detector (FR-13)

**Files:**
- Create: `src/Detectors/PluginIntegrityDetector.php`
- Test: `tests/Detectors/PluginIntegrityDetectorTest.php`

**Interfaces:**
- Consumes: `ChecksumClient::getPluginChecksums(string $slug, string $version): ?array` from Task 10; `OptionsRepository::getActivePlugins(): array` from Task 4 (returns strings like `akismet/akismet.php` — slug is `dirname()` of that string).
- Produces: `AdyaSoft\Security\Detectors\PluginIntegrityDetector`, method `detect(array $currentScan, string $pluginSlug, array $pluginChecksums): array` — for every path in `$currentScan` starting with `wp-content/plugins/{$pluginSlug}/` whose relative-to-plugin-root path is in `$pluginChecksums` with a differing hash → `plugin_checksum_mismatch`. (Files not in the plugin's official manifest are *not* flagged here — unlike core, plugins commonly ship generated/optional files not in the checksum manifest, so absence alone isn't a signal; only a hash *mismatch* on a file the manifest does know about is.) This method handles one plugin per call; the caller (Task 16) loops over `OptionsRepository::getActivePlugins()`.

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/Detectors/PluginIntegrityDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\PluginIntegrityDetector;
use PHPUnit\Framework\TestCase;

final class PluginIntegrityDetectorTest extends TestCase
{
    private function entry(string $sha): array
    {
        return ['sha256' => $sha, 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsChecksumMismatchForPluginFile(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/akismet.php' => $this->entry('modified-hash')],
            'akismet',
            ['akismet.php' => 'original-hash'],
        );

        $this->assertSame('plugin_checksum_mismatch', $findings[0]['type']);
        $this->assertSame('wp-content/plugins/akismet/akismet.php', $findings[0]['path']);
    }

    public function testDoesNotFlagFileMissingFromManifest(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/generated-cache.php' => $this->entry('x')],
            'akismet',
            ['akismet.php' => 'original-hash'],
        );

        $this->assertSame([], $findings);
    }

    public function testIgnoresFilesFromOtherPlugins(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/other-plugin/main.php' => $this->entry('x')],
            'akismet',
            ['main.php' => 'y'],
        );

        $this->assertSame([], $findings);
    }

    public function testNoFindingsWhenHashMatches(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/akismet.php' => $this->entry('same-hash')],
            'akismet',
            ['akismet.php' => 'same-hash'],
        );

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/PluginIntegrityDetectorTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `PluginIntegrityDetector`**

```php
<?php
// src/Detectors/PluginIntegrityDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class PluginIntegrityDetector
{
    public function detect(array $currentScan, string $pluginSlug, array $pluginChecksums): array
    {
        $prefix = "wp-content/plugins/{$pluginSlug}/";
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, $prefix)) {
                continue;
            }

            $relativeToPlugin = substr($path, strlen($prefix));
            if (!isset($pluginChecksums[$relativeToPlugin])) {
                continue;
            }

            if ($pluginChecksums[$relativeToPlugin] !== $entry['sha256']) {
                $findings[] = [
                    'type' => 'plugin_checksum_mismatch',
                    'path' => $path,
                    'details' => ['plugin' => $pluginSlug, 'expected' => $pluginChecksums[$relativeToPlugin], 'actual' => $entry['sha256']],
                ];
            }
        }

        return $findings;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/PluginIntegrityDetectorTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/Detectors/PluginIntegrityDetector.php tests/Detectors/PluginIntegrityDetectorTest.php
git commit -m "feat: add plugin checksum integrity detector (FR-13)"
```

---

### Task 12: PHP entropy/obfuscation analyzer (FR-8)

**Files:**
- Create: `src/Detectors/EntropyAnalyzer.php`
- Test: `tests/Detectors/EntropyAnalyzerTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\Detectors\EntropyAnalyzer::__construct(float $entropyThreshold = 4.5, int $minStringLength = 40)`, method `analyzeFile(string $absolutePath): array` — reads the file, returns findings `['type' => 'entropy_high'|'entropy_obfuscation_pattern', 'path' => ..., 'details' => [...]]` (path is the *absolute* path passed in; caller in Task 16 is responsible for recording the relative path in the merged report). Two independent checks, both can fire on the same file:
  - `entropy_high`: any single-quoted or double-quoted string literal (found via `token_get_all`, `T_CONSTANT_ENCAPSED_STRING`) of length ≥ `$minStringLength` whose Shannon entropy ≥ `$entropyThreshold` bits/char.
  - `entropy_obfuscation_pattern`: source contains any of a fixed set of suspicious call patterns via regex: chained `eval(base64_decode(`, `eval(gzinflate(`, `eval(str_rot13(`, `assert(` called with a variable/string argument, `create_function(`, dynamic variable-variable invocation `$$`, or `call_user_func` / `call_user_func_array` whose first argument comes directly from `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`.

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/Detectors/EntropyAnalyzerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\EntropyAnalyzer;
use PHPUnit\Framework\TestCase;

final class EntropyAnalyzerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/entropy-' . uniqid('', true) . '.php';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testFlagsHighEntropyStringLiteral(): void
    {
        // A long, high-entropy (effectively random-looking) base64 blob.
        $blob = 'ZGVhZGJlZWZjb2ZmZWViYWJlMTIzNDU2Nzg5MHFiY2RlZm9wcXJzdHV2d3l6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
        file_put_contents($this->path, "<?php\n\$x = '{$blob}';\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_high', $types);
    }

    public function testDoesNotFlagOrdinaryShortStrings(): void
    {
        file_put_contents($this->path, "<?php\necho 'hello world';\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $this->assertSame([], $findings);
    }

    public function testFlagsEvalBase64DecodeChain(): void
    {
        file_put_contents($this->path, "<?php\neval(base64_decode(\$_POST['x']));\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_obfuscation_pattern', $types);
    }

    public function testFlagsCallUserFuncFedFromRequestSuperglobal(): void
    {
        file_put_contents($this->path, "<?php\ncall_user_func(\$_GET['fn'], 'arg');\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_obfuscation_pattern', $types);
    }

    public function testDoesNotFlagOrdinaryFunctionCalls(): void
    {
        file_put_contents($this->path, "<?php\nfunction add(\$a, \$b) { return \$a + \$b; }\necho add(1, 2);\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $this->assertSame([], $findings);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Detectors/EntropyAnalyzerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `EntropyAnalyzer`**

```php
<?php
// src/Detectors/EntropyAnalyzer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class EntropyAnalyzer
{
    private const OBFUSCATION_PATTERNS = [
        '/eval\s*\(\s*base64_decode\s*\(/i',
        '/eval\s*\(\s*gzinflate\s*\(/i',
        '/eval\s*\(\s*gzuncompress\s*\(/i',
        '/eval\s*\(\s*str_rot13\s*\(/i',
        '/assert\s*\(\s*\$/i',
        '/create_function\s*\(/i',
        '/\$\$[a-zA-Z_]/',
        '/call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/i',
    ];

    public function __construct(
        private readonly float $entropyThreshold = 4.5,
        private readonly int $minStringLength = 40,
    ) {
    }

    public function analyzeFile(string $absolutePath): array
    {
        $source = file_get_contents($absolutePath);
        if ($source === false) {
            return [];
        }

        $findings = [];

        if ($this->hasHighEntropyStringLiteral($source)) {
            $findings[] = ['type' => 'entropy_high', 'path' => $absolutePath, 'details' => []];
        }

        foreach (self::OBFUSCATION_PATTERNS as $pattern) {
            if (preg_match($pattern, $source) === 1) {
                $findings[] = ['type' => 'entropy_obfuscation_pattern', 'path' => $absolutePath, 'details' => ['pattern' => $pattern]];
                break; // one finding per file is enough signal; details carries which pattern
            }
        }

        return $findings;
    }

    private function hasHighEntropyStringLiteral(string $source): bool
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens)) {
            return false;
        }

        foreach ($tokens as $token) {
            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }
            $literal = trim($token[1], '\'"');
            if (strlen($literal) >= $this->minStringLength && $this->shannonEntropy($literal) >= $this->entropyThreshold) {
                return true;
            }
        }

        return false;
    }

    private function shannonEntropy(string $data): float
    {
        $length = strlen($data);
        if ($length === 0) {
            return 0.0;
        }

        $frequencies = array_count_values(str_split($data));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Detectors/EntropyAnalyzerTest.php`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/Detectors/EntropyAnalyzer.php tests/Detectors/EntropyAnalyzerTest.php
git commit -m "feat: add PHP entropy and obfuscation-pattern analyzer (FR-8)"
```

---

### Task 13: Composite risk scorer & severity bands (FR-9, FR-28)

**Files:**
- Create: `src/Scoring/RiskScorer.php`
- Test: `tests/Scoring/RiskScorerTest.php`

**Interfaces:**
- Consumes: `config/scoring.php` shape from Task 1 (`weights: [signal_type => int]`, `severity_thresholds: [BAND => int]`); a finding list where every finding has a `type` key, in the shape produced by every detector in Tasks 5–12.
- Produces: `AdyaSoft\Security\Scoring\RiskScorer::__construct(array $weights, array $severityThresholds)`, method `score(array $findings): array` — groups findings that share the same "subject" (see below) and returns a list of `['subject' => ..., 'findings' => [...], 'composite_score' => int, 'severity' => 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL']`. The "subject" key groups multiple signals about the *same thing* into one scored item (FR-9's "composite score per finding, combining multiple independent signals, rather than flagging on any single signal alone") — for a file finding that's `path`, for a user finding that's `user_login`, for a page finding that's `page_id`, for an `.htaccess` finding that's the fixed string `.htaccess`. `score()` derives the subject per finding as: `$finding['path'] ?? $finding['user_login'] ?? $finding['page_id'] ?? '.htaccess'`.

  Severity is picked by finding the highest threshold in `$severityThresholds` (sorted descending by threshold value) whose value the composite score meets or exceeds.

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/Scoring/RiskScorerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Scoring;

use AdyaSoft\Security\Scoring\RiskScorer;
use PHPUnit\Framework\TestCase;

final class RiskScorerTest extends TestCase
{
    private function weights(): array
    {
        return [
            'file_new' => 20,
            'file_in_uploads_is_php' => 40,
            'entropy_obfuscation_pattern' => 30,
            'user_not_in_known_good_roster' => 50,
        ];
    }

    private function thresholds(): array
    {
        return ['CRITICAL' => 70, 'HIGH' => 45, 'MEDIUM' => 20, 'LOW' => 0];
    }

    public function testCombinesMultipleSignalsForTheSameFileIntoOneCompositeScore(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $findings = [
            ['type' => 'file_new', 'path' => 'wp-content/uploads/shell.php'],
            ['type' => 'file_in_uploads_is_php', 'path' => 'wp-content/uploads/shell.php'],
            ['type' => 'entropy_obfuscation_pattern', 'path' => 'wp-content/uploads/shell.php'],
        ];

        $scored = $scorer->score($findings);

        $this->assertCount(1, $scored);
        $this->assertSame('wp-content/uploads/shell.php', $scored[0]['subject']);
        $this->assertSame(90, $scored[0]['composite_score']); // 20 + 40 + 30
        $this->assertSame('CRITICAL', $scored[0]['severity']);
        $this->assertCount(3, $scored[0]['findings']);
    }

    public function testSeparatesDifferentSubjectsIntoDifferentScoredItems(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $findings = [
            ['type' => 'file_new', 'path' => 'a.php'],
            ['type' => 'user_not_in_known_good_roster', 'user_login' => 'rogue'],
        ];

        $scored = $scorer->score($findings);

        $subjects = array_column($scored, 'subject');
        sort($subjects);
        $this->assertSame(['a.php', 'rogue'], $subjects);
    }

    public function testAssignsLowSeverityWhenBelowAllHigherThresholds(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $scored = $scorer->score([['type' => 'file_new', 'path' => 'a.php']]);

        $this->assertSame(20, $scored[0]['composite_score']);
        $this->assertSame('MEDIUM', $scored[0]['severity']);
    }

    public function testUnknownSignalTypeContributesZeroWeightButIsStillIncluded(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $scored = $scorer->score([['type' => 'some_future_signal', 'path' => 'a.php']]);

        $this->assertSame(0, $scored[0]['composite_score']);
        $this->assertSame('LOW', $scored[0]['severity']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Scoring/RiskScorerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `RiskScorer`**

```php
<?php
// src/Scoring/RiskScorer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Scoring;

final class RiskScorer
{
    public function __construct(
        private readonly array $weights,
        private readonly array $severityThresholds,
    ) {
    }

    public function score(array $findings): array
    {
        $grouped = [];

        foreach ($findings as $finding) {
            $subject = $finding['path'] ?? $finding['user_login'] ?? $finding['page_id'] ?? '.htaccess';
            $grouped[$subject][] = $finding;
        }

        $scored = [];
        foreach ($grouped as $subject => $subjectFindings) {
            $compositeScore = 0;
            foreach ($subjectFindings as $finding) {
                $compositeScore += $this->weights[$finding['type']] ?? 0;
            }

            $scored[] = [
                'subject' => $subject,
                'findings' => $subjectFindings,
                'composite_score' => $compositeScore,
                'severity' => $this->severityFor($compositeScore),
            ];
        }

        return $scored;
    }

    private function severityFor(int $compositeScore): string
    {
        $thresholds = $this->severityThresholds;
        arsort($thresholds);

        foreach ($thresholds as $band => $threshold) {
            if ($compositeScore >= $threshold) {
                return $band;
            }
        }

        return 'LOW';
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Scoring/RiskScorerTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/Scoring/RiskScorer.php tests/Scoring/RiskScorerTest.php
git commit -m "feat: add composite risk scorer and severity bands (FR-9, FR-28)"
```

---

### Task 14: Report builder (FR-29)

**Files:**
- Create: `src/Reporting/ReportBuilder.php`
- Test: `tests/Reporting/ReportBuilderTest.php`

**Interfaces:**
- Consumes: `RiskScorer::score()` output shape from Task 13; a `site_id`/`site_path`/`scan_id`/`mode` metadata bundle.
- Produces: `AdyaSoft\Security\Reporting\ReportBuilder`, method `build(array $meta, array $scoredFindings): array` — `$meta` requires keys `site_id`, `site_path`, `scan_id`, `mode`, `scanned_at`. Returns the full structured report array:
  ```
  [
    'meta' => [...$meta],
    'summary' => ['total_findings' => int, 'by_severity' => ['CRITICAL' => int, 'HIGH' => int, 'MEDIUM' => int, 'LOW' => int]],
    'findings' => $scoredFindings, // sorted CRITICAL -> HIGH -> MEDIUM -> LOW, ties by subject
  ]
  ```
- Produces: method `toJson(array $report): string` (pretty-printed JSON, FR-29's structured report) and `toHumanReadable(array $report): string` (plain-text summary: meta line, counts by severity, then one line per scored item — `"[{severity}] {subject} (score {n}): {comma-separated finding types}"`).

- [ ] **Step 1: Write the failing test**

```php
<?php
// tests/Reporting/ReportBuilderTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\ReportBuilder;
use PHPUnit\Framework\TestCase;

final class ReportBuilderTest extends TestCase
{
    private function meta(): array
    {
        return ['site_id' => 'abc123', 'site_path' => '/home/user/public_html', 'scan_id' => 'scan-1', 'mode' => 'audit', 'scanned_at' => '2026-08-17T00:00:00+00:00'];
    }

    public function testBuildIncludesMetaAndSortsFindingsBySeverityDescending(): void
    {
        $builder = new ReportBuilder();

        $scored = [
            ['subject' => 'low-thing', 'findings' => [['type' => 'file_new']], 'composite_score' => 10, 'severity' => 'LOW'],
            ['subject' => 'critical-thing', 'findings' => [['type' => 'file_in_uploads_is_php']], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'high-thing', 'findings' => [['type' => 'core_file_checksum_mismatch']], 'composite_score' => 50, 'severity' => 'HIGH'],
        ];

        $report = $builder->build($this->meta(), $scored);

        $this->assertSame('abc123', $report['meta']['site_id']);
        $severities = array_column($report['findings'], 'severity');
        $this->assertSame(['CRITICAL', 'HIGH', 'LOW'], $severities);
    }

    public function testBuildComputesSummaryCountsBySeverity(): void
    {
        $builder = new ReportBuilder();
        $scored = [
            ['subject' => 'a', 'findings' => [], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'b', 'findings' => [], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'c', 'findings' => [], 'composite_score' => 10, 'severity' => 'LOW'],
        ];

        $report = $builder->build($this->meta(), $scored);

        $this->assertSame(3, $report['summary']['total_findings']);
        $this->assertSame(2, $report['summary']['by_severity']['CRITICAL']);
        $this->assertSame(0, $report['summary']['by_severity']['HIGH']);
        $this->assertSame(0, $report['summary']['by_severity']['MEDIUM']);
        $this->assertSame(1, $report['summary']['by_severity']['LOW']);
    }

    public function testToJsonProducesValidJsonRoundTrippingTheReport(): void
    {
        $builder = new ReportBuilder();
        $report = $builder->build($this->meta(), []);

        $json = $builder->toJson($report);

        $this->assertSame($report, json_decode($json, true));
    }

    public function testToHumanReadableIncludesSiteIdAndOneLinePerFinding(): void
    {
        $builder = new ReportBuilder();
        $scored = [
            ['subject' => 'wp-content/uploads/shell.php', 'findings' => [['type' => 'file_new'], ['type' => 'file_in_uploads_is_php']], 'composite_score' => 60, 'severity' => 'HIGH'],
        ];
        $report = $builder->build($this->meta(), $scored);

        $text = $builder->toHumanReadable($report);

        $this->assertStringContainsString('abc123', $text);
        $this->assertStringContainsString('[HIGH] wp-content/uploads/shell.php (score 60): file_new, file_in_uploads_is_php', $text);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Reporting/ReportBuilderTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `ReportBuilder`**

```php
<?php
// src/Reporting/ReportBuilder.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class ReportBuilder
{
    private const SEVERITY_ORDER = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];

    public function build(array $meta, array $scoredFindings): array
    {
        usort($scoredFindings, static function (array $a, array $b): int {
            $orderA = self::SEVERITY_ORDER[$a['severity']] ?? 99;
            $orderB = self::SEVERITY_ORDER[$b['severity']] ?? 99;
            return $orderA <=> $orderB ?: $a['subject'] <=> $b['subject'];
        });

        $bySeverity = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
        foreach ($scoredFindings as $item) {
            $bySeverity[$item['severity']] = ($bySeverity[$item['severity']] ?? 0) + 1;
        }

        return [
            'meta' => $meta,
            'summary' => [
                'total_findings' => count($scoredFindings),
                'by_severity' => $bySeverity,
            ],
            'findings' => $scoredFindings,
        ];
    }

    public function toJson(array $report): string
    {
        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function toHumanReadable(array $report): string
    {
        $lines = [];
        $lines[] = sprintf(
            'Scan report — site %s (%s) — %s — mode: %s',
            $report['meta']['site_id'],
            $report['meta']['site_path'],
            $report['meta']['scanned_at'],
            $report['meta']['mode'],
        );
        $lines[] = sprintf(
            'Total findings: %d (CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)',
            $report['summary']['total_findings'],
            $report['summary']['by_severity']['CRITICAL'],
            $report['summary']['by_severity']['HIGH'],
            $report['summary']['by_severity']['MEDIUM'],
            $report['summary']['by_severity']['LOW'],
        );
        $lines[] = '';

        foreach ($report['findings'] as $item) {
            $types = implode(', ', array_column($item['findings'], 'type'));
            $lines[] = sprintf('[%s] %s (score %d): %s', $item['severity'], $item['subject'], $item['composite_score'], $types);
        }

        return implode("\n", $lines);
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Reporting/ReportBuilderTest.php`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/Reporting/ReportBuilder.php tests/Reporting/ReportBuilderTest.php
git commit -m "feat: add report builder producing structured JSON + human-readable output (FR-29)"
```

---

### Task 15: Mailer / alerting & digest (FR-30, FR-31)

**Files:**
- Create: `src/Reporting/Mailer.php`
- Create: `src/Reporting/DigestQueue.php`
- Test: `tests/Reporting/MailerTest.php`
- Test: `tests/Reporting/DigestQueueTest.php`

**Interfaces:**
- Produces: `AdyaSoft\Security\Reporting\Mailer::__construct(callable $sendMail, array $mailConfig)` — `$sendMail` has signature `(string $to, string $subject, string $body): bool`, injected so tests never send real mail; `$mailConfig` is the `config/mail.php` shape (`from`, `to`, `alert_on_bands`, `digest_hour_utc`). Method `sendAlertIfNeeded(array $report, string $humanReadableBody): bool` — returns `true` and calls `$sendMail` (subject includes site_id and highest severity present) only if `$report['findings']` contains at least one item whose `severity` is in `$mailConfig['alert_on_bands']`; otherwise returns `false` and does not call `$sendMail` (FR-31's "suppresses routine no-finding notifications").
- Produces: `AdyaSoft\Security\Reporting\DigestQueue::__construct(string $queuePath)`, methods `append(array $reportSummaryLine): void` (queues one line — used for scans that didn't trigger `sendAlertIfNeeded`), `flush(): array` (returns all queued lines and empties the queue file — called once/day by the cron-driven expensive-tier run to compose and send the digest).

- [ ] **Step 1: Write the failing test for `Mailer`**

```php
<?php
// tests/Reporting/MailerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\Mailer;
use PHPUnit\Framework\TestCase;

final class MailerTest extends TestCase
{
    private function mailConfig(): array
    {
        return ['from' => 'scanner@example.com', 'to' => ['ops@example.com'], 'alert_on_bands' => ['CRITICAL', 'HIGH'], 'digest_hour_utc' => 6];
    }

    private function reportWithSeverities(array $severities): array
    {
        $findings = [];
        foreach ($severities as $severity) {
            $findings[] = ['subject' => 'x', 'findings' => [], 'composite_score' => 0, 'severity' => $severity];
        }
        return ['meta' => ['site_id' => 'site-a'], 'summary' => [], 'findings' => $findings];
    }

    public function testSendsAlertWhenCriticalFindingPresent(): void
    {
        $sent = null;
        $mailer = new Mailer(function (string $to, string $subject, string $body) use (&$sent): bool {
            $sent = compact('to', 'subject', 'body');
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities(['CRITICAL']), 'body text');

        $this->assertTrue($result);
        $this->assertSame('ops@example.com', $sent['to']);
        $this->assertStringContainsString('site-a', $sent['subject']);
    }

    public function testDoesNotSendWhenOnlyLowAndMediumFindingsPresent(): void
    {
        $called = false;
        $mailer = new Mailer(function () use (&$called): bool {
            $called = true;
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities(['MEDIUM', 'LOW']), 'body text');

        $this->assertFalse($result);
        $this->assertFalse($called);
    }

    public function testDoesNotSendWhenNoFindingsAtAll(): void
    {
        $called = false;
        $mailer = new Mailer(function () use (&$called): bool {
            $called = true;
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities([]), 'body text');

        $this->assertFalse($result);
        $this->assertFalse($called);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Reporting/MailerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `Mailer`**

```php
<?php
// src/Reporting/Mailer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class Mailer
{
    /** @param callable(string, string, string): bool $sendMail */
    public function __construct(
        private readonly mixed $sendMail,
        private readonly array $mailConfig,
    ) {
    }

    public function sendAlertIfNeeded(array $report, string $humanReadableBody): bool
    {
        $alertBands = $this->mailConfig['alert_on_bands'];
        $highestBand = null;

        foreach ($report['findings'] as $item) {
            if (in_array($item['severity'], $alertBands, true)) {
                $highestBand = $item['severity'];
                break; // findings are pre-sorted by severity descending (ReportBuilder)
            }
        }

        if ($highestBand === null) {
            return false;
        }

        $subject = sprintf('[%s] Security finding on %s', $highestBand, $report['meta']['site_id']);

        foreach ($this->mailConfig['to'] as $recipient) {
            ($this->sendMail)($recipient, $subject, $humanReadableBody);
        }

        return true;
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Reporting/MailerTest.php`
Expected: PASS (3 tests)

- [ ] **Step 5: Write the failing test for `DigestQueue`**

```php
<?php
// tests/Reporting/DigestQueueTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\DigestQueue;
use PHPUnit\Framework\TestCase;

final class DigestQueueTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/digest-' . uniqid('', true) . '.jsonl';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testAppendThenFlushReturnsAllQueuedEntries(): void
    {
        $queue = new DigestQueue($this->path);

        $queue->append(['site_id' => 'a', 'summary' => 'clean scan']);
        $queue->append(['site_id' => 'b', 'summary' => 'clean scan']);

        $entries = $queue->flush();

        $this->assertCount(2, $entries);
        $this->assertSame('a', $entries[0]['site_id']);
    }

    public function testFlushEmptiesTheQueue(): void
    {
        $queue = new DigestQueue($this->path);
        $queue->append(['site_id' => 'a', 'summary' => 'clean scan']);

        $queue->flush();
        $second = $queue->flush();

        $this->assertSame([], $second);
    }

    public function testFlushOnEmptyQueueReturnsEmptyArray(): void
    {
        $queue = new DigestQueue($this->path);

        $this->assertSame([], $queue->flush());
    }
}
```

- [ ] **Step 6: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/Reporting/DigestQueueTest.php`
Expected: FAIL — class not found.

- [ ] **Step 7: Implement `DigestQueue`**

```php
<?php
// src/Reporting/DigestQueue.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class DigestQueue
{
    public function __construct(private readonly string $queuePath)
    {
    }

    public function append(array $entry): void
    {
        $dir = dirname($this->queuePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->queuePath, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    public function flush(): array
    {
        if (!is_file($this->queuePath)) {
            return [];
        }

        $lines = file($this->queuePath, FILE_IGNORE_NEW_LINES) ?: [];
        unlink($this->queuePath);

        return array_map(static fn (string $line) => json_decode($line, true), $lines);
    }
}
```

- [ ] **Step 8: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/Reporting/DigestQueueTest.php`
Expected: PASS (3 tests)

- [ ] **Step 9: Commit**

```bash
git add src/Reporting/Mailer.php src/Reporting/DigestQueue.php tests/Reporting/MailerTest.php tests/Reporting/DigestQueueTest.php
git commit -m "feat: add alert mailer and clean-scan digest queue (FR-30, FR-31)"
```

---

### Task 16: Main entrypoint, mode enforcement, and end-to-end smoke test (FR-34, FR-35, NFR-8)

**Files:**
- Create: `src/Scanner.php`
- Modify: `bin/run.php`
- Test: `tests/ScannerTest.php`

**Interfaces:**
- Consumes: every class produced in Tasks 2–15.
- Produces: `AdyaSoft\Security\Scanner::__construct(string $dataDir, array $scoringConfig, array $mailConfig, array $sitesConfig)`, method `scanSite(string $sitePath, string $siteId, string $tier): array` where `$tier` is `'cheap'` (users, pages, htaccess only — NFR-8's 1–4 hour cadence) or `'expensive'` (everything, including files/core/plugin/entropy — daily cadence). Returns the built report array (Task 14 shape) with `meta.mode` always `'audit'` (FR-34/35 — hardcoded, not a flag, per spec A10). Internally: DB-backed detectors (users/pages/plugins) are skipped with a logged warning if `WpConfigParser::parse()` returns `null` for that site (spec A4's documented risk), and the rest of the tier still runs.
- Modifies `bin/run.php` to: parse `--checks=cheap|expensive|all` and optional `--account-home=` from `$argv`; instantiate `SiteDiscoverer`/`ManifestStore` to enumerate sites; call `Scanner::scanSite()` per active site; route each report through `Mailer::sendAlertIfNeeded()` and `DigestQueue::append()` when not alerted; flush and email the digest once/day when the current UTC hour matches `mail.php`'s `digest_hour_utc`.

- [ ] **Step 1: Write the failing test for `Scanner` (end-to-end wiring against a fixture site + in-memory SQLite)**

```php
<?php
// tests/ScannerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests;

use AdyaSoft\Security\Scanner;
use PHPUnit\Framework\TestCase;

final class ScannerTest extends TestCase
{
    private string $dataDir;
    private string $siteDir;

    protected function setUp(): void
    {
        $this->dataDir = sys_get_temp_dir() . '/scanner-data-' . uniqid('', true);
        $this->siteDir = sys_get_temp_dir() . '/scanner-site-' . uniqid('', true);
        mkdir($this->siteDir . '/wp-content', 0700, true);
        mkdir($this->siteDir . '/wp-admin', 0700, true);
        mkdir($this->siteDir . '/wp-includes', 0700, true);
        file_put_contents(
            $this->siteDir . '/wp-config.php',
            "<?php\ndefine('DB_NAME', 'testdb');\ndefine('DB_USER', 'u');\ndefine('DB_PASSWORD', 'p');\ndefine('DB_HOST', 'localhost');\n\$table_prefix = 'wp_';\n"
        );
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->dataDir);
        $this->removeDir($this->siteDir);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function testScanSiteWithUnparseableDbCredsSkipsDbChecksButStillRunsHtaccess(): void
    {
        // wp-config.php in setUp() IS parseable, so overwrite it with something the
        // parser can't handle, to exercise the "needs_manual_config" fallback path.
        file_put_contents($this->siteDir . '/wp-config.php', "<?php\n// no defines here\n");
        file_put_contents($this->siteDir . '/.htaccess', "RewriteEngine On\n");

        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';
        $mailConfig = require dirname(__DIR__) . '/config/mail.php';

        $scanner = new Scanner($this->dataDir, $scoringConfig, $mailConfig, []);
        $report = $scanner->scanSite($this->siteDir, 'site-a', 'cheap');

        $this->assertSame('audit', $report['meta']['mode']);
        $this->assertSame('site-a', $report['meta']['site_id']);
        // .htaccess appearing for the first time is itself a finding (no baseline yet).
        $subjects = array_column($report['findings'], 'subject');
        $this->assertContains('.htaccess', $subjects);
    }

    public function testModeIsAlwaysAuditRegardlessOfInput(): void
    {
        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';
        $mailConfig = require dirname(__DIR__) . '/config/mail.php';

        $scanner = new Scanner($this->dataDir, $scoringConfig, $mailConfig, []);
        $report = $scanner->scanSite($this->siteDir, 'site-a', 'expensive');

        $this->assertSame('audit', $report['meta']['mode']);
    }
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `vendor/bin/phpunit tests/ScannerTest.php`
Expected: FAIL — class not found.

- [ ] **Step 3: Implement `Scanner`**

```php
<?php
// src/Scanner.php
declare(strict_types=1);

namespace AdyaSoft\Security;

use AdyaSoft\Security\Baseline\FileBaselineStore;
use AdyaSoft\Security\Baseline\FileScanner;
use AdyaSoft\Security\Baseline\HtaccessBaselineStore;
use AdyaSoft\Security\Baseline\PageBaselineStore;
use AdyaSoft\Security\Baseline\UserBaselineStore;
use AdyaSoft\Security\Detectors\CoreIntegrityDetector;
use AdyaSoft\Security\Detectors\EntropyAnalyzer;
use AdyaSoft\Security\Detectors\FileDetector;
use AdyaSoft\Security\Detectors\HtaccessDetector;
use AdyaSoft\Security\Detectors\MuPluginsDetector;
use AdyaSoft\Security\Detectors\PageDetector;
use AdyaSoft\Security\Detectors\PluginIntegrityDetector;
use AdyaSoft\Security\Detectors\UploadsPhpDetector;
use AdyaSoft\Security\Detectors\UserDetector;
use AdyaSoft\Security\Reporting\ReportBuilder;
use AdyaSoft\Security\Scoring\RiskScorer;
use AdyaSoft\Security\Support\Logger;
use AdyaSoft\Security\WordPress\ChecksumClient;
use AdyaSoft\Security\WordPress\DbConnectionFactory;
use AdyaSoft\Security\WordPress\OptionsRepository;
use AdyaSoft\Security\WordPress\PageRepository;
use AdyaSoft\Security\WordPress\UserRepository;
use AdyaSoft\Security\WordPress\WpConfigParser;

final class Scanner
{
    public function __construct(
        private readonly string $dataDir,
        private readonly array $scoringConfig,
        private readonly array $mailConfig,
        private readonly array $sitesConfig,
    ) {
    }

    public function scanSite(string $sitePath, string $siteId, string $tier): array
    {
        $siteDataDir = "{$this->dataDir}/sites/{$siteId}";
        $logger = new Logger("{$siteDataDir}/scans/{$this->scanId($siteId)}.log");
        $siteOverrides = $this->sitesConfig[$siteId] ?? [];
        $knownGoodUsers = $siteOverrides['known_good_users'] ?? [];
        $knownContributors = $siteOverrides['known_contributor_logins'] ?? $knownGoodUsers;
        $siteDomains = $siteOverrides['domains'] ?? [];

        $findings = [];

        // --- users, pages, active plugins: require a parseable wp-config.php ---
        $credentials = null;
        if (is_file("{$sitePath}/wp-config.php")) {
            $credentials = WpConfigParser::parse(file_get_contents("{$sitePath}/wp-config.php"));
        }

        $activePlugins = [];
        if ($credentials === null) {
            $logger->warning('wp-config.php not parseable; skipping DB-backed checks', ['site_id' => $siteId]);
        } else {
            try {
                $pdo = DbConnectionFactory::createMysql($credentials);

                $userRepo = new UserRepository($pdo, $credentials['table_prefix']);
                $userBaselineStore = new UserBaselineStore("{$siteDataDir}/baseline/users.json");
                $previousUsers = $userBaselineStore->load();
                $currentUsers = $userRepo->findAdminAndEditorUsers();
                $findings = array_merge($findings, (new UserDetector($knownGoodUsers))->detect($currentUsers, $previousUsers));
                $userBaselineStore->save($currentUsers);

                $pageRepo = new PageRepository($pdo, $credentials['table_prefix']);
                $pageBaselineStore = new PageBaselineStore("{$siteDataDir}/baseline/pages.json");
                $previousPages = $pageBaselineStore->load();
                $currentPages = $pageRepo->findPublishedPages();
                $findings = array_merge($findings, (new PageDetector($knownContributors))->detect($currentPages, $previousPages));
                $pageBaselineStore->save($currentPages);

                if ($tier === 'expensive') {
                    $activePlugins = (new OptionsRepository($pdo, $credentials['table_prefix']))->getActivePlugins();
                }
            } catch (\PDOException $e) {
                $logger->error('DB connection failed; skipping DB-backed checks', ['error' => $e->getMessage()]);
            }
        }

        // --- .htaccess: filesystem only, always runs ---
        $htaccessBaselineStore = new HtaccessBaselineStore("{$siteDataDir}/baseline/htaccess.json.txt");
        $previousHtaccess = $htaccessBaselineStore->load();
        $currentHtaccess = is_file("{$sitePath}/.htaccess") ? file_get_contents("{$sitePath}/.htaccess") : null;
        $findings = array_merge($findings, (new HtaccessDetector($siteDomains))->detect($currentHtaccess, $previousHtaccess));
        if ($currentHtaccess !== null) {
            $htaccessBaselineStore->save($currentHtaccess);
        }

        // --- expensive tier: files, core/plugin integrity, entropy ---
        if ($tier === 'expensive') {
            $fileBaselineStore = new FileBaselineStore("{$siteDataDir}/baseline/files.json");
            $previousFiles = $fileBaselineStore->load();
            $currentFiles = (new FileScanner($sitePath))->scan();

            $findings = array_merge($findings, (new FileDetector())->detect($currentFiles, $previousFiles));
            $findings = array_merge($findings, (new UploadsPhpDetector())->detect($currentFiles));
            $findings = array_merge($findings, (new MuPluginsDetector())->detect($currentFiles, $previousFiles));

            $checksumClient = new ChecksumClient(static function (string $url): ?array {
                $json = @file_get_contents($url);
                if ($json === false) {
                    return null;
                }
                $decoded = json_decode($json, true);
                return is_array($decoded) ? $decoded : null;
            });

            if (is_file("{$sitePath}/wp-includes/version.php")) {
                $wpVersion = $this->readWpVersion("{$sitePath}/wp-includes/version.php");
                $coreChecksums = $wpVersion !== null ? $checksumClient->getCoreChecksums($wpVersion) : null;
                if ($coreChecksums !== null) {
                    $findings = array_merge($findings, (new CoreIntegrityDetector())->detect($currentFiles, $coreChecksums));
                } else {
                    $logger->warning('core checksums unavailable; skipping core integrity check', ['version' => $wpVersion]);
                }
            }

            foreach ($activePlugins as $pluginFile) {
                $slug = dirname($pluginFile);
                if ($slug === '.') {
                    continue;
                }
                $pluginVersion = $this->readPluginVersion("{$sitePath}/wp-content/plugins/{$pluginFile}");
                if ($pluginVersion === null) {
                    $logger->warning('plugin version header not found; skipping checksum check', ['plugin' => $slug]);
                    continue;
                }
                $pluginChecksums = $checksumClient->getPluginChecksums($slug, $pluginVersion);
                if ($pluginChecksums !== null) {
                    $findings = array_merge($findings, (new PluginIntegrityDetector())->detect($currentFiles, $slug, $pluginChecksums));
                } else {
                    $logger->warning('plugin checksums unavailable; skipping check', ['plugin' => $slug, 'version' => $pluginVersion]);
                }
            }

            $entropyAnalyzer = new EntropyAnalyzer();
            foreach (array_keys($currentFiles) as $relativePath) {
                if (strtolower(pathinfo($relativePath, PATHINFO_EXTENSION)) !== 'php') {
                    continue;
                }
                foreach ($entropyAnalyzer->analyzeFile("{$sitePath}/{$relativePath}") as $entropyFinding) {
                    $entropyFinding['path'] = $relativePath;
                    $findings[] = $entropyFinding;
                }
            }

            $fileBaselineStore->save($currentFiles);
        }

        $scorer = new RiskScorer($this->scoringConfig['weights'], $this->scoringConfig['severity_thresholds']);
        $scored = $scorer->score($findings);

        $report = (new ReportBuilder())->build([
            'site_id' => $siteId,
            'site_path' => $sitePath,
            'scan_id' => $this->scanId($siteId),
            'mode' => 'audit',
            'scanned_at' => date('c'),
            'tier' => $tier,
        ], $scored);

        file_put_contents(
            "{$siteDataDir}/scans/{$report['meta']['scan_id']}.json",
            (new ReportBuilder())->toJson($report)
        );

        $logger->info('scan complete', ['total_findings' => $report['summary']['total_findings']]);

        return $report;
    }

    private function readWpVersion(string $versionFilePath): ?string
    {
        $wp_version = null;
        (function () use ($versionFilePath, &$wp_version): void {
            include $versionFilePath;
        })();
        return $wp_version;
    }

    private function readPluginVersion(string $pluginMainFilePath): ?string
    {
        if (!is_file($pluginMainFilePath)) {
            return null;
        }

        $header = file_get_contents($pluginMainFilePath, false, null, 0, 8192);
        if ($header === false) {
            return null;
        }

        if (preg_match('/^\s*(?:\*|\/\*+)?\s*Version:\s*(.+)$/mi', $header, $matches) === 1) {
            return trim($matches[1]);
        }

        return null;
    }

    private function scanId(string $siteId): string
    {
        static $ids = [];
        return $ids[$siteId] ??= $siteId . '-' . date('Ymd-His');
    }
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `vendor/bin/phpunit tests/ScannerTest.php`
Expected: PASS (2 tests) — the DB connection attempt in `testScanSiteWithUnparseableDbCredsSkipsDbChecksButStillRunsHtaccess` never happens because the credentials are unparseable, so no live MySQL is needed; `testModeIsAlwaysAuditRegardlessOfInput` hits the same unparseable-creds path from `setUp()`'s deliberately-broken `wp-config.php`.

- [ ] **Step 5: Wire up `bin/run.php`**

```php
<?php
// bin/run.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Security\Discovery\ManifestStore;
use AdyaSoft\Security\Discovery\SiteDiscoverer;
use AdyaSoft\Security\Reporting\DigestQueue;
use AdyaSoft\Security\Reporting\Mailer;
use AdyaSoft\Security\Reporting\ReportBuilder;
use AdyaSoft\Security\Scanner;
use AdyaSoft\Security\Support\ConfigLoader;
use AdyaSoft\Security\Support\Logger;

$options = getopt('', ['checks:', 'account-home:']);
$tier = $options['checks'] ?? 'all';
$accountHome = $options['account-home'] ?? dirname(__DIR__, 2); // default: parent of security-scanner/

if (!in_array($tier, ['cheap', 'expensive', 'all'], true)) {
    fwrite(STDERR, "Invalid --checks value: {$tier}. Use cheap, expensive, or all.\n");
    exit(1);
}

$rootDir = dirname(__DIR__);
$dataDir = "{$rootDir}/data";

$scoringConfig = ConfigLoader::load("{$rootDir}/config/scoring.php");
$mailConfig = ConfigLoader::load("{$rootDir}/config/mail.php");
$sitesConfig = ConfigLoader::load("{$rootDir}/config/sites.php");

$logger = new Logger("{$dataDir}/run.log");
$logger->info('discovery started', ['account_home' => $accountHome]);

$discoverer = new SiteDiscoverer($accountHome);
$discovered = $discoverer->discover();

$manifestStore = new ManifestStore("{$dataDir}/manifest.json");
$manifest = $manifestStore->reconcile($manifestStore->load(), $discovered);
$manifestStore->save($manifest);

$mailer = new Mailer(
    static function (string $to, string $subject, string $body): bool {
        return mail($to, $subject, $body);
    },
    $mailConfig,
);
$digestQueue = new DigestQueue("{$dataDir}/digest-queue.jsonl");
$reportBuilder = new ReportBuilder();
$scanner = new Scanner($dataDir, $scoringConfig, $mailConfig, $sitesConfig);

$tiersToRun = $tier === 'all' ? ['cheap', 'expensive'] : [$tier];

foreach ($manifest as $siteId => $entry) {
    if ($entry['status'] !== 'active') {
        continue;
    }

    foreach ($tiersToRun as $runTier) {
        $report = $scanner->scanSite($entry['path'], $siteId, $runTier);
        $humanReadable = $reportBuilder->toHumanReadable($report);

        $alerted = $mailer->sendAlertIfNeeded($report, $humanReadable);
        if (!$alerted) {
            $digestQueue->append([
                'site_id' => $siteId,
                'scanned_at' => $report['meta']['scanned_at'],
                'total_findings' => $report['summary']['total_findings'],
            ]);
        }
    }
}

if ((int) date('G') === (int) $mailConfig['digest_hour_utc']) {
    $entries = $digestQueue->flush();
    if ($entries !== []) {
        $body = "Daily digest — clean/no-alert scans:\n\n" . implode("\n", array_map(
            static fn (array $e) => sprintf('%s: %d findings at %s', $e['site_id'], $e['total_findings'], $e['scanned_at']),
            $entries,
        ));
        foreach ($mailConfig['to'] as $recipient) {
            mail($recipient, 'Security scanner daily digest', $body);
        }
    }
}

$logger->info('run complete', ['sites_scanned' => count($manifest)]);
```

- [ ] **Step 6: Run the full test suite**

Run: `vendor/bin/phpunit`
Expected: PASS (all tests across every task)

- [ ] **Step 7: Manually smoke-test `bin/run.php` against the fixture site created in Step 1's test, confirming it exits 0 and writes a report**

```bash
mkdir -p /tmp/manual-smoke/public_html/wp-content /tmp/manual-smoke/public_html/wp-admin /tmp/manual-smoke/public_html/wp-includes
cat > /tmp/manual-smoke/public_html/wp-config.php <<'EOF'
<?php
// intentionally unparseable to avoid needing a live MySQL for this smoke test
EOF
php bin/run.php --checks=cheap --account-home=/tmp/manual-smoke
cat data/manifest.json
```
Expected: exits 0, `data/manifest.json` contains one active site, and `data/sites/<id>/scans/*.json` exists with `mode: "audit"`.

- [ ] **Step 8: Commit**

```bash
git add src/Scanner.php bin/run.php tests/ScannerTest.php
git commit -m "feat: wire up main entrypoint with tiered scans and mode enforcement (FR-34, FR-35, NFR-8)"
```

---

## Self-Review Notes

- **Spec coverage:** every P0 FR listed in spec A11 maps to a task above (FR-1/2 → Task 2; FR-4-10 → Tasks 8-9; FR-12/13 → Tasks 10-11; FR-16-18 → Task 5; FR-20-22 → Task 6; FR-25/26 → Task 7; FR-8 → Task 12; FR-9/28 → Task 13; FR-29 → Task 14; FR-30/31 → Task 15; FR-34/35 → Task 16). Governing NFRs are enforced structurally (A3/A4 no-shell-exec and DB-direct access baked into every WordPress-touching class; A6 storage layout in every baseline store's path; A9 no-runtime-deps via the hand-rolled autoloader used even in `tests/bootstrap.php`).
- **Deferred (not in this plan):** FR-3, FR-11, FR-14, FR-15, FR-19, FR-23, FR-24, FR-27, FR-32, FR-33, FR-36–42 — see spec A11.
- **Type consistency:** finding shape (`type`, plus `path`/`user_login`/`page_id` as the subject key, plus `details`) is used identically by every detector in Tasks 5–12 and consumed identically by `RiskScorer::score()` in Task 13 and `Scanner::scanSite()` in Task 16.
