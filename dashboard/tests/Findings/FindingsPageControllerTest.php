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
