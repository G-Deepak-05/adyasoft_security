<?php
// dashboard/tests/Fixtures/SqliteDashboardSchema.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Fixtures;

final class SqliteDashboardSchema
{
    public static function createInMemoryDb(): \PDO
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $pdo->exec('CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key_hash TEXT NOT NULL,
            revoked_at TEXT NULL,
            created_at TEXT NOT NULL
        )');

        $pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )');

        $pdo->exec('CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            site_id TEXT NOT NULL,
            site_label TEXT NULL,
            scan_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            severity TEXT NOT NULL,
            composite_score INTEGER NOT NULL,
            finding_type TEXT NOT NULL,
            details TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            UNIQUE(account_id, scan_id, subject, finding_type)
        )');

        return $pdo;
    }
}
