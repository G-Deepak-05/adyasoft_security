<?php
// src/Baseline/FileBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class FileBaselineStore
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
        return is_array($decoded) ? $decoded : [];
    }

    public function save(array $entries): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
