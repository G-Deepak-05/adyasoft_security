<?php
// src/Detectors/PluginIntegrityDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class PluginIntegrityDetector
{
    public function detect(array $currentScan, string $pluginSlug, array $pluginChecksums): array
    {
        $prefix = "wp-content/plugins/{$pluginSlug}/";
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, $prefix)) {
                continue;
            }

            $relativeToPlugin = substr($path, strlen($prefix));
            if (!isset($pluginChecksums[$relativeToPlugin])) {
                continue;
            }

            if ($pluginChecksums[$relativeToPlugin] !== $entry['sha256']) {
                $findings[] = [
                    'type' => 'plugin_checksum_mismatch',
                    'path' => $path,
                    'details' => ['plugin' => $pluginSlug, 'expected' => $pluginChecksums[$relativeToPlugin], 'actual' => $entry['sha256']],
                ];
            }
        }

        return $findings;
    }
}
