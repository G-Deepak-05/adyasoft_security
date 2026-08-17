<?php
// src/WordPress/OptionsRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class OptionsRepository
{
    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function getActivePlugins(): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT option_value FROM {$this->tablePrefix}options WHERE option_name = 'active_plugins' LIMIT 1"
        );
        $stmt->execute();
        $value = $stmt->fetchColumn();

        if ($value === false) {
            return [];
        }

        $unserialized = @unserialize($value, ['allowed_classes' => false]);
        return is_array($unserialized) ? $unserialized : [];
    }
}
