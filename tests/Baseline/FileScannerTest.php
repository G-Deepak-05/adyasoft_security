<?php
// tests/Baseline/FileScannerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\FileScanner;
use PHPUnit\Framework\TestCase;

final class FileScannerTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/filescan-' . uniqid('', true);
        mkdir($this->root . '/wp-content', 0700, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function testScanReturnsHashSizeMtimeAndPermissionsForEachFile(): void
    {
        file_put_contents($this->root . '/wp-content/index.php', '<?php // silence');

        $scanner = new FileScanner($this->root);
        $result = $scanner->scan();

        $this->assertArrayHasKey('wp-content/index.php', $result);
        $entry = $result['wp-content/index.php'];
        $this->assertSame(hash_file('sha256', $this->root . '/wp-content/index.php'), $entry['sha256']);
        $this->assertSame(filesize($this->root . '/wp-content/index.php'), $entry['size']);
        $this->assertArrayHasKey('mtime', $entry);
        $this->assertArrayHasKey('permissions', $entry);
    }

    public function testScanUsesForwardSlashRelativePathsAcrossNestedDirs(): void
    {
        mkdir($this->root . '/wp-content/uploads/2024', 0700, true);
        file_put_contents($this->root . '/wp-content/uploads/2024/photo.jpg', 'data');

        $scanner = new FileScanner($this->root);
        $result = $scanner->scan();

        $this->assertArrayHasKey('wp-content/uploads/2024/photo.jpg', $result);
    }

    public function testScanExcludesSymlinksPointingOutsideRoot(): void
    {
        // Create a file outside the scanned root
        $externalFile = sys_get_temp_dir() . '/external-' . uniqid('', true) . '.txt';
        file_put_contents($externalFile, 'sensitive data');

        try {
            // Create a symlink inside the scanned root pointing to the external file
            $symlinkPath = $this->root . '/wp-content/external-link.txt';
            symlink($externalFile, $symlinkPath);

            $scanner = new FileScanner($this->root);
            $result = $scanner->scan();

            // The symlink's relative path should NOT be in the results
            $this->assertArrayNotHasKey('wp-content/external-link.txt', $result);
        } finally {
            // Clean up: unlink the symlink itself, then the external file
            if (is_link($symlinkPath ?? null)) {
                unlink($symlinkPath);
            }
            if (is_file($externalFile)) {
                unlink($externalFile);
            }
        }
    }
}
