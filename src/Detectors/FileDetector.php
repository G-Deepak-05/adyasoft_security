<?php
// src/Detectors/FileDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class FileDetector
{
    public function detect(array $currentScan, array $baseline): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!isset($baseline[$path])) {
                $findings[] = ['type' => 'file_new', 'path' => $path, 'details' => $entry];
            } elseif ($baseline[$path] !== $entry) {
                $findings[] = ['type' => 'file_modified', 'path' => $path, 'details' => ['before' => $baseline[$path], 'after' => $entry]];
            }
        }

        foreach ($baseline as $path => $entry) {
            if (!isset($currentScan[$path])) {
                $findings[] = ['type' => 'file_deleted', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
