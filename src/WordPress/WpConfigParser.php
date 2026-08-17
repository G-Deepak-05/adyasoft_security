<?php
// src/WordPress/WpConfigParser.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class WpConfigParser
{
    public static function parse(string $wpConfigContents): ?array
    {
        $dbName = self::extractDefine($wpConfigContents, 'DB_NAME');
        $dbUser = self::extractDefine($wpConfigContents, 'DB_USER');
        $dbPassword = self::extractDefine($wpConfigContents, 'DB_PASSWORD');
        $dbHost = self::extractDefine($wpConfigContents, 'DB_HOST');
        $tablePrefix = self::extractTablePrefix($wpConfigContents);

        if ($dbName === null || $dbUser === null || $dbPassword === null
            || $dbHost === null || $tablePrefix === null) {
            return null;
        }

        return [
            'db_name' => $dbName,
            'db_user' => $dbUser,
            'db_password' => $dbPassword,
            'db_host' => $dbHost,
            'table_prefix' => $tablePrefix,
        ];
    }

    private static function extractDefine(string $contents, string $constant): ?string
    {
        $pattern = '/define\s*\(\s*[\'"]' . preg_quote($constant, '/')
            . '[\'"]\s*,\s*[\'"]((?:[^\'"\\\\]|\\\\.)*)[\'"]\s*\)/';

        if (preg_match($pattern, $contents, $matches) === 1) {
            return stripslashes($matches[1]);
        }

        return null;
    }

    private static function extractTablePrefix(string $contents): ?string
    {
        $pattern = '/\$table_prefix\s*=\s*[\'"]([a-zA-Z0-9_]*)[\'"]\s*;/';

        if (preg_match($pattern, $contents, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }
}
