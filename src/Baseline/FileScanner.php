<?php
// src/Baseline/FileScanner.php
declare(strict_types=1);

namespace AdyaSoft\Security\Baseline;

final class FileScanner
{
    public function __construct(private readonly string $siteRootPath)
    {
    }

    public function scan(): array
    {
        $root = rtrim($this->siteRootPath, '/');
        $results = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY,
        );

        foreach ($iterator as $fileInfo) {
            /** @var \SplFileInfo $fileInfo */
            if ($fileInfo->isLink()) {
                continue;
            }
            if (!$fileInfo->isFile()) {
                continue;
            }
            $absolutePath = $fileInfo->getPathname();
            $relativePath = ltrim(substr($absolutePath, strlen($root)), '/');

            $results[$relativePath] = [
                'sha256' => hash_file('sha256', $absolutePath),
                'size' => $fileInfo->getSize(),
                'mtime' => $fileInfo->getMTime(),
                'permissions' => substr(sprintf('%o', $fileInfo->getPerms()), -4),
            ];
        }

        return $results;
    }
}
