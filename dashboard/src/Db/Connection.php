<?php
// dashboard/src/Db/Connection.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Db;

final class Connection
{
    public static function create(array $config): \PDO
    {
        return new \PDO($config['dsn'], $config['user'] ?? null, $config['password'] ?? null, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        ]);
    }
}
