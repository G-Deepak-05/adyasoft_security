<?php
// src/Baseline/UserBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class UserBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $decoded = json_decode(file_get_contents($this->baselinePath), true);
        if (!is_array($decoded)) {
            error_log("Corrupted JSON in {$this->baselinePath}, resetting to empty state");
            return [];
        }
        return $decoded;
    }

    public function save(array $users): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
