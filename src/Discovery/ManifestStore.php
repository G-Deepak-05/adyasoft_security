<?php
// src/Discovery/ManifestStore.php
declare(strict_types=1);

namespace AdyaSoft\Security\Discovery;

final class ManifestStore
{
    public function __construct(private readonly string $manifestPath)
    {
    }

    public function load(): array
    {
        if (!is_file($this->manifestPath)) {
            return [];
        }
        $contents = file_get_contents($this->manifestPath);
        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            error_log("Corrupted JSON in {$this->manifestPath}, resetting to empty state");
            return [];
        }
        return $decoded;
    }

    public function save(array $manifest): void
    {
        $dir = dirname($this->manifestPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents(
            $this->manifestPath,
            json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
    }

    /**
     * @param array $manifest existing manifest, keyed by site_id
     * @param string[] $discoveredPaths absolute paths found by SiteDiscoverer this run
     */
    public function reconcile(array $manifest, array $discoveredPaths): array
    {
        $now = date('c');
        $byPath = [];
        foreach ($manifest as $siteId => $entry) {
            $byPath[$entry['path']] = $siteId;
        }

        $discoveredSet = array_flip($discoveredPaths);

        foreach ($discoveredPaths as $path) {
            if (isset($byPath[$path])) {
                $siteId = $byPath[$path];
                $manifest[$siteId]['status'] = 'active';
                $manifest[$siteId]['last_seen'] = $now;
            } else {
                $siteId = substr(sha1($path), 0, 12);
                $manifest[$siteId] = [
                    'site_id' => $siteId,
                    'path' => $path,
                    'first_seen' => $now,
                    'last_seen' => $now,
                    'status' => 'active',
                ];
            }
        }

        foreach ($manifest as $siteId => $entry) {
            if (!isset($discoveredSet[$entry['path']])) {
                $manifest[$siteId]['status'] = 'missing';
            }
        }

        return $manifest;
    }
}
