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

    public function testTwoFindingsOfTheSameTypeUnderOneSubjectMergeInsteadOfAbortingTheScan(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $ingester = new FindingsIngester($pdo);

        // HtaccessDetector emits one htaccess_external_redirect finding per
        // malicious redirect target; RiskScorer groups them all under '.htaccess'.
        $rowsInserted = $ingester->ingest($accountId, [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => 'scan-htaccess',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => '.htaccess',
                    'severity' => 'CRITICAL',
                    'composite_score' => 95,
                    'findings' => [
                        ['type' => 'htaccess_external_redirect', 'details' => ['target' => 'http://evil-one.example']],
                        ['type' => 'htaccess_external_redirect', 'details' => ['target' => 'http://evil-two.example']],
                    ],
                ],
            ],
        ]);

        $this->assertSame(1, $rowsInserted);

        $rows = $pdo->query('SELECT * FROM findings')->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertCount(1, $rows);
        $this->assertSame('htaccess_external_redirect', $rows[0]['finding_type']);
        $this->assertSame('.htaccess', $rows[0]['subject']);

        // Neither redirect target may be silently dropped.
        $details = json_decode($rows[0]['details'], true);
        $this->assertSame(
            [
                'details' => [
                    ['target' => 'http://evil-one.example'],
                    ['target' => 'http://evil-two.example'],
                ],
            ],
            $details,
        );
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
