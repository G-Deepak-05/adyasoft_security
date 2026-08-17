<?php
// tests/Baseline/UserBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\UserBaselineStore;
use PHPUnit\Framework\TestCase;

final class UserBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/user-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new UserBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new UserBaselineStore($this->path);
        $users = [['id' => 1, 'user_login' => 'boss', 'user_email' => 'boss@example.com', 'user_registered' => '2024-01-01', 'roles' => ['administrator']]];

        $store->save($users);

        $this->assertSame($users, $store->load());
    }
}
