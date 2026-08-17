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

        // The report must actually be persisted to disk, not just returned in memory.
        $this->assertFileExists(
            "{$this->dataDir}/sites/site-a/scans/{$report['meta']['scan_id']}.json"
        );
    }

    public function testModeIsAlwaysAuditRegardlessOfInput(): void
    {
        // Use an unparseable wp-config.php so this test never attempts a real DB
        // connection (setUp()'s fixture is deliberately parseable, which would
        // otherwise make this test silently try to connect to MySQL on localhost).
        file_put_contents($this->siteDir . '/wp-config.php', "<?php\n// no defines here\n");

        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';
        $mailConfig = require dirname(__DIR__) . '/config/mail.php';

        $scanner = new Scanner($this->dataDir, $scoringConfig, $mailConfig, []);
        $report = $scanner->scanSite($this->siteDir, 'site-a', 'expensive');

        $this->assertSame('audit', $report['meta']['mode']);

        // The report must actually be persisted to disk, not just returned in memory.
        $this->assertFileExists(
            "{$this->dataDir}/sites/site-a/scans/{$report['meta']['scan_id']}.json"
        );
    }
}
