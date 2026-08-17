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
