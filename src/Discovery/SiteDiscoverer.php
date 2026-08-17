<?php
// src/Discovery/SiteDiscoverer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Discovery;

final class SiteDiscoverer
{
    private const MAX_DEPTH = 6;

    public function __construct(
        private readonly string $accountHomePath,
        private readonly array $excludeDirs = ['security-scanner'],
    ) {
    }

    /** @return string[] absolute paths of discovered WordPress installations */
    public function discover(): array
    {
        $found = [];
        $this->walk(rtrim($this->accountHomePath, '/'), 0, $found);
        sort($found);
        return $found;
    }

    private function walk(string $dir, int $depth, array &$found): void
    {
        if ($depth > self::MAX_DEPTH || !is_dir($dir)) {
            return;
        }

        if ($this->isWordPressInstallation($dir)) {
            $found[] = $dir;
            return; // don't descend into a discovered site's own tree
        }

        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if (in_array($entry, $this->excludeDirs, true)) {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                $this->walk($path, $depth + 1, $found);
            }
        }
    }

    private function isWordPressInstallation(string $dir): bool
    {
        return is_file($dir . '/wp-config.php')
            && is_dir($dir . '/wp-content')
            && is_dir($dir . '/wp-admin')
            && is_dir($dir . '/wp-includes');
    }
}
