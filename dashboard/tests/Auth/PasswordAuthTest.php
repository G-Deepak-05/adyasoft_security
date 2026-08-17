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
