<?php
// src/Support/Logger.php
declare(strict_types=1);

namespace AdyaSoft\Security\Support;

final class Logger
{
    public function __construct(private readonly string $logFilePath)
    {
    }

    public function info(string $message, array $context = []): void
    {
        $this->write('info', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->write('warning', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->write('error', $message, $context);
    }

    private function write(string $level, string $message, array $context): void
    {
        $dir = dirname($this->logFilePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        $line = json_encode([
            'ts' => date('c'),
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ], JSON_UNESCAPED_SLASHES);

        file_put_contents($this->logFilePath, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
