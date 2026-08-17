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
