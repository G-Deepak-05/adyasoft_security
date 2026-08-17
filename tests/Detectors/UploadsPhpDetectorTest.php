<?php
// tests/Detectors/UploadsPhpDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\UploadsPhpDetector;
use PHPUnit\Framework\TestCase;

final class UploadsPhpDetectorTest extends TestCase
{
    private function entry(): array
    {
        return ['sha256' => 'x', 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsPhpFileUnderUploads(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect(['wp-content/uploads/2024/shell.php' => $this->entry()]);

        $this->assertSame('file_in_uploads_is_php', $findings[0]['type']);
        $this->assertSame('wp-content/uploads/2024/shell.php', $findings[0]['path']);
    }

    public function testFlagsCaseInsensitiveAndAlternateExtensions(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect([
            'wp-content/uploads/a.PHP' => $this->entry(),
            'wp-content/uploads/b.phtml' => $this->entry(),
        ]);

        $this->assertCount(2, $findings);
    }

    public function testDoesNotFlagNonPhpFilesOrFilesOutsideUploads(): void
    {
        $detector = new UploadsPhpDetector();

        $findings = $detector->detect([
            'wp-content/uploads/2024/photo.jpg' => $this->entry(),
            'wp-content/plugins/some-plugin/handler.php' => $this->entry(),
        ]);

        $this->assertSame([], $findings);
    }
}
