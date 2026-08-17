<?php
// src/Support/ConfigLoader.php
declare(strict_types=1);

namespace AdyaSoft\Security\Support;

final class ConfigLoader
{
    public static function load(string $configPath): array
    {
        if (!is_file($configPath)) {
            throw new \RuntimeException("Config file not found: {$configPath}");
        }

        return require $configPath;
    }
}
