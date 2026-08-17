<?php
// src/Baseline/HtaccessBaselineStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class HtaccessBaselineStore
{
    public function __construct(private readonly string $baselinePath)
    {
    }

    public function load(): ?string
    {
        if (!is_file($this->baselinePath)) {
            return null;
        }
        return file_get_contents($this->baselinePath);
    }

    public function save(string $contents): void
    {
        $dir = dirname($this->baselinePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->baselinePath, $contents);
    }
}
