<?php
// src/Detectors/UploadsPhpDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class UploadsPhpDetector
{
    private const PHP_EXTENSIONS = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar'];

    public function detect(array $currentScan): array
    {
        $findings = [];

        foreach ($currentScan as $path => $entry) {
            if (!str_starts_with($path, 'wp-content/uploads/')) {
                continue;
            }
            $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (in_array($extension, self::PHP_EXTENSIONS, true)) {
                $findings[] = ['type' => 'file_in_uploads_is_php', 'path' => $path, 'details' => $entry];
            }
        }

        return $findings;
    }
}
