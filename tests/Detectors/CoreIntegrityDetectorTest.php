<?php
// tests/Detectors/CoreIntegrityDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\CoreIntegrityDetector;
use PHPUnit\Framework\TestCase;

final class CoreIntegrityDetectorTest extends TestCase
{
    private function entry(string $sha): array
    {
        return ['sha256' => $sha, 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsCoreFileNotInOfficialManifest(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-admin/backdoor.php' => $this->entry('x')],
            ['wp-admin/index.php' => 'abc123'],
        );

        $this->assertSame('core_file_not_in_manifest', $findings[0]['type']);
        $this->assertSame('wp-admin/backdoor.php', $findings[0]['path']);
    }

    public function testFlagsChecksumMismatchForKnownCoreFile(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-admin/index.php' => $this->entry('modified-hash')],
            ['wp-admin/index.php' => 'original-hash'],
        );

        $this->assertSame('core_file_checksum_mismatch', $findings[0]['type']);
    }

    public function testIgnoresFilesOutsideCoreDirectories(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/foo.php' => $this->entry('x')],
            [],
        );

        $this->assertSame([], $findings);
    }

    public function testNoFindingsWhenHashMatchesManifest(): void
    {
        $detector = new CoreIntegrityDetector();

        $findings = $detector->detect(
            ['wp-includes/version.php' => $this->entry('matching-hash')],
            ['wp-includes/version.php' => 'matching-hash'],
        );

        $this->assertSame([], $findings);
    }
}
