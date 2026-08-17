<?php
// src/Detectors/CoreIntegrityDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class CoreIntegrityDetector
{
    public function detect(array $currentScan, array $officialChecksums): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-admin/') && !str_starts_with($path, 'wp-includes/')) {
                continue;
            }

            if (!isset($officialChecksums[$path])) {
                $findings[] = ['type' => 'core_file_not_in_manifest', 'path' => $path, 'details' => $entry];
            } elseif ($officialChecksums[$path] !== $entry['sha256']) {
                $findings[] = [
                    'type' => 'core_file_checksum_mismatch',
                    'path' => $path,
                    'details' => ['expected' => $officialChecksums[$path], 'actual' => $entry['sha256']],
                ];
            }
        }

        return $findings;
    }
}
