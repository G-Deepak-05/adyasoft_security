<?php
// tests/ScannerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests;

use AdyaSoft\Security\Scanner;
use PHPUnit\Framework\TestCase;

final class ScannerTest extends TestCase
{
    /** Must match ManifestStore::reconcile()'s 12-char hex site_id format. */
    private const SITE_ID = 'a1b2c3d4e5f6';

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

        $scanner = new Scanner($this->dataDir, $scoringConfig, []);
        $report = $scanner->scanSite($this->siteDir, self::SITE_ID, 'cheap');

        $this->assertSame('audit', $report['meta']['mode']);
        $this->assertSame(self::SITE_ID, $report['meta']['site_id']);
        // .htaccess appearing for the first time is itself a finding (no baseline yet).
        $subjects = array_column($report['findings'], 'subject');
        $this->assertContains('.htaccess', $subjects);

        // Spec A4: a skipped check must be visible in the report itself, not only in the
        // log — otherwise a degraded scan is indistinguishable from a genuinely clean one.
        $this->assertSame(
            ['DB-backed checks skipped: wp-config.php not parseable'],
            $report['meta']['degraded_checks']
        );

        // The report must actually be persisted to disk, not just returned in memory.
        $this->assertFileExists(
            "{$this->dataDir}/sites/" . self::SITE_ID . "/scans/{$report['meta']['scan_id']}.json"
        );
    }

    public function testScanIdIsDistinctPerTierSoTiersDoNotOverwriteEachOther(): void
    {
        file_put_contents($this->siteDir . '/wp-config.php', "<?php\n// no defines here\n");

        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';
        $scanner = new Scanner($this->dataDir, $scoringConfig, []);

        $cheap = $scanner->scanSite($this->siteDir, self::SITE_ID, 'cheap');
        $expensive = $scanner->scanSite($this->siteDir, self::SITE_ID, 'expensive');

        $this->assertNotSame($cheap['meta']['scan_id'], $expensive['meta']['scan_id']);
        // Both reports must survive on disk; a shared scan_id would overwrite the first.
        $this->assertFileExists("{$this->dataDir}/sites/" . self::SITE_ID . "/scans/{$cheap['meta']['scan_id']}.json");
        $this->assertFileExists("{$this->dataDir}/sites/" . self::SITE_ID . "/scans/{$expensive['meta']['scan_id']}.json");
    }

    public function testRejectsSiteIdThatIsNotAManifestDerivedHexId(): void
    {
        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';
        $scanner = new Scanner($this->dataDir, $scoringConfig, []);

        $this->expectException(\InvalidArgumentException::class);
        $scanner->scanSite($this->siteDir, '../../etc', 'cheap');
    }

    public function testModeIsAlwaysAuditRegardlessOfInput(): void
    {
        // Use an unparseable wp-config.php so this test never attempts a real DB
        // connection (setUp()'s fixture is deliberately parseable, which would
        // otherwise make this test silently try to connect to MySQL on localhost).
        file_put_contents($this->siteDir . '/wp-config.php', "<?php\n// no defines here\n");

        $scoringConfig = require dirname(__DIR__) . '/config/scoring.php';

        $scanner = new Scanner($this->dataDir, $scoringConfig, []);
        $report = $scanner->scanSite($this->siteDir, self::SITE_ID, 'expensive');

        $this->assertSame('audit', $report['meta']['mode']);

        // The report must actually be persisted to disk, not just returned in memory.
        $this->assertFileExists(
            "{$this->dataDir}/sites/" . self::SITE_ID . "/scans/{$report['meta']['scan_id']}.json"
        );
    }
}
