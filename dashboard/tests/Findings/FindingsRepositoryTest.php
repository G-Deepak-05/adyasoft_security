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

    public function testDateOnlyToFilterIncludesFindingsScannedLaterThatSameDay(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'late.php', 'HIGH', 'file_new', '2026-08-17T23:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search(['to' => '2026-08-17'], 1, 50);

        $this->assertSame(1, $result['total']);
        $this->assertSame('late.php', $result['rows'][0]['subject']);
    }

    public function testDateOnlyToFilterExcludesTheFollowingDay(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $accountId = (new AccountRepository($pdo))->create('client-a')['id'];
        $this->seed($pdo, $accountId, 'scan-1', 'late.php', 'HIGH', 'file_new', '2026-08-17T23:00:00+00:00');
        $this->seed($pdo, $accountId, 'scan-2', 'next.php', 'HIGH', 'file_new', '2026-08-18T00:00:00+00:00');

        $result = (new FindingsRepository($pdo))->search(['to' => '2026-08-17'], 1, 50);

        $this->assertSame(1, $result['total']);
        $this->assertSame('late.php', $result['rows'][0]['subject']);
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
