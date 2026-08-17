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
