<?php
// dashboard/tests/Fixtures/SqliteDashboardSchemaTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Fixtures;

use PHPUnit\Framework\TestCase;

final class SqliteDashboardSchemaTest extends TestCase
{
    public function testCreatesAllThreeTables(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();

        $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")
            ->fetchAll(\PDO::FETCH_COLUMN);

        $this->assertContains('accounts', $tables);
        $this->assertContains('users', $tables);
        $this->assertContains('findings', $tables);
    }
}
