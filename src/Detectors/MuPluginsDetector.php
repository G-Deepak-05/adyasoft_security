<?php
// src/Detectors/MuPluginsDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class MuPluginsDetector
{
    public function detect(array $currentScan, array $baseline): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-content/mu-plugins/')) {
                continue;
            }
            if (!isset($baseline[$path])) {
                $findings[] = ['type' => 'file_in_mu_plugins_new', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
