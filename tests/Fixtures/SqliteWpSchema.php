<?php
// tests/Fixtures/SqliteWpSchema.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Fixtures;

final class SqliteWpSchema
{
    public static function createInMemoryDb(string $prefix = 'wp_'): \PDO
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $pdo->exec("CREATE TABLE {$prefix}users (
            ID INTEGER PRIMARY KEY,
            user_login TEXT,
            user_email TEXT,
            user_registered TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}usermeta (
            umeta_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            meta_key TEXT,
            meta_value TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}posts (
            ID INTEGER PRIMARY KEY,
            post_author INTEGER,
            post_title TEXT,
            post_name TEXT,
            post_content TEXT,
            post_status TEXT,
            post_type TEXT,
            post_date TEXT,
            post_modified TEXT
        )");

        $pdo->exec("CREATE TABLE {$prefix}options (
            option_id INTEGER PRIMARY KEY,
            option_name TEXT,
            option_value TEXT
        )");

        return $pdo;
    }

    public static function insertUser(
        \PDO $pdo,
        string $prefix,
        int $id,
        string $login,
        string $email,
        string $registered,
        array $roles,
    ): void {
        $pdo->prepare("INSERT INTO {$prefix}users (ID, user_login, user_email, user_registered) VALUES (?, ?, ?, ?)")
            ->execute([$id, $login, $email, $registered]);

        $serializedRoles = 'a:' . count($roles) . ':{';
        foreach ($roles as $role) {
            $serializedRoles .= 's:1:"1";s:' . strlen($role) . ':"' . $role . '";';
        }
        $serializedRoles .= '}';

        $pdo->prepare("INSERT INTO {$prefix}usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)")
            ->execute([$id, "{$prefix}capabilities", $serializedRoles]);
    }

    public static function insertPage(
        \PDO $pdo,
        string $prefix,
        int $id,
        int $authorId,
        string $title,
        string $slug,
        string $content,
        string $publishedAt,
        string $modifiedAt,
    ): void {
        $pdo->prepare(
            "INSERT INTO {$prefix}posts (ID, post_author, post_title, post_name, post_content, post_status, post_type, post_date, post_modified)
             VALUES (?, ?, ?, ?, ?, 'publish', 'page', ?, ?)"
        )->execute([$id, $authorId, $title, $slug, $content, $publishedAt, $modifiedAt]);
    }

    public static function setOption(\PDO $pdo, string $prefix, string $name, string $serializedValue): void
    {
        $pdo->prepare("INSERT INTO {$prefix}options (option_name, option_value) VALUES (?, ?)")
            ->execute([$name, $serializedValue]);
    }
}
