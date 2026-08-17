<?php
// src/Reporting/DigestQueue.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class DigestQueue
{
    public function __construct(private readonly string $queuePath)
    {
    }

    public function append(array $entry): void
    {
        $dir = dirname($this->queuePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($this->queuePath, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    public function flush(): array
    {
        if (!is_file($this->queuePath)) {
            return [];
        }

        $lines = file($this->queuePath, FILE_IGNORE_NEW_LINES) ?: [];
        unlink($this->queuePath);

        return array_map(static fn (string $line) => json_decode($line, true), $lines);
    }
}
