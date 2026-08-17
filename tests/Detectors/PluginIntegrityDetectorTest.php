<?php
// tests/Detectors/PluginIntegrityDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\PluginIntegrityDetector;
use PHPUnit\Framework\TestCase;

final class PluginIntegrityDetectorTest extends TestCase
{
    private function entry(string $sha): array
    {
        return ['sha256' => $sha, 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsChecksumMismatchForPluginFile(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/akismet.php' => $this->entry('modified-hash')],
            'akismet',
            ['akismet.php' => 'original-hash'],
        );

        $this->assertSame('plugin_checksum_mismatch', $findings[0]['type']);
        $this->assertSame('wp-content/plugins/akismet/akismet.php', $findings[0]['path']);
    }

    public function testDoesNotFlagFileMissingFromManifest(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/generated-cache.php' => $this->entry('x')],
            'akismet',
            ['akismet.php' => 'original-hash'],
        );

        $this->assertSame([], $findings);
    }

    public function testIgnoresFilesFromOtherPlugins(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/other-plugin/main.php' => $this->entry('x')],
            'akismet',
            ['main.php' => 'y'],
        );

        $this->assertSame([], $findings);
    }

    public function testNoFindingsWhenHashMatches(): void
    {
        $detector = new PluginIntegrityDetector();

        $findings = $detector->detect(
            ['wp-content/plugins/akismet/akismet.php' => $this->entry('same-hash')],
            'akismet',
            ['akismet.php' => 'same-hash'],
        );

        $this->assertSame([], $findings);
    }
}
