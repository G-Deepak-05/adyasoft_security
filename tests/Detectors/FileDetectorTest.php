<?php
// tests/Detectors/FileDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\FileDetector;
use PHPUnit\Framework\TestCase;

final class FileDetectorTest extends TestCase
{
    private function entry(string $sha = 'abc', int $size = 10, int $mtime = 100, string $perms = '0644'): array
    {
        return ['sha256' => $sha, 'size' => $size, 'mtime' => $mtime, 'permissions' => $perms];
    }

    public function testFlagsNewFile(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(['shell.php' => $this->entry()], []);

        $this->assertSame('file_new', $findings[0]['type']);
        $this->assertSame('shell.php', $findings[0]['path']);
    }

    public function testFlagsModifiedFileWhenHashDiffers(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(
            ['index.php' => $this->entry('newhash')],
            ['index.php' => $this->entry('oldhash')],
        );

        $this->assertSame('file_modified', $findings[0]['type']);
    }

    public function testFlagsModifiedFileWhenSizeDiffers(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(
            ['index.php' => $this->entry(sha: 'abc', size: 20)],
            ['index.php' => $this->entry(sha: 'abc', size: 10)],
        );

        $this->assertSame('file_modified', $findings[0]['type']);
    }

    public function testFlagsModifiedFileWhenMtimeDiffers(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(
            ['index.php' => $this->entry(sha: 'abc', mtime: 200)],
            ['index.php' => $this->entry(sha: 'abc', mtime: 100)],
        );

        $this->assertSame('file_modified', $findings[0]['type']);
    }

    public function testFlagsModifiedFileWhenPermissionsDiffer(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect(
            ['index.php' => $this->entry(sha: 'abc', perms: '0755')],
            ['index.php' => $this->entry(sha: 'abc', perms: '0644')],
        );

        $this->assertSame('file_modified', $findings[0]['type']);
    }

    public function testFlagsDeletedFile(): void
    {
        $detector = new FileDetector();

        $findings = $detector->detect([], ['index.php' => $this->entry()]);

        $this->assertSame('file_deleted', $findings[0]['type']);
    }

    public function testNoFindingsForUnchangedFile(): void
    {
        $detector = new FileDetector();
        $entry = $this->entry();

        $findings = $detector->detect(['index.php' => $entry], ['index.php' => $entry]);

        $this->assertSame([], $findings);
    }
}
