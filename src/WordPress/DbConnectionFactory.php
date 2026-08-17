<?php
// src/WordPress/DbConnectionFactory.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class DbConnectionFactory
{
    public static function createMysql(array $credentials): \PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            $credentials['db_host'],
            $credentials['db_name'],
        );

        return new \PDO($dsn, $credentials['db_user'], $credentials['db_password'], [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_TIMEOUT => 5,
        ]);
    }
}
