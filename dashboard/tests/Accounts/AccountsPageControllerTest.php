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
