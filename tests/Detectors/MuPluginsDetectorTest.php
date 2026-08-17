<?php
// tests/Detectors/MuPluginsDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\MuPluginsDetector;
use PHPUnit\Framework\TestCase;

final class MuPluginsDetectorTest extends TestCase
{
    private function entry(): array
    {
        return ['sha256' => 'x', 'size' => 1, 'mtime' => 1, 'permissions' => '0644'];
    }

    public function testFlagsNewFileInMuPlugins(): void
    {
        $detector = new MuPluginsDetector();

        $findings = $detector->detect(['wp-content/mu-plugins/backdoor.php' => $this->entry()], []);

        $this->assertSame('file_in_mu_plugins_new', $findings[0]['type']);
    }

    public function testDoesNotFlagExistingBaselinedMuPlugin(): void
    {
        $detector = new MuPluginsDetector();
        $entry = $this->entry();

        $findings = $detector->detect(
            ['wp-content/mu-plugins/legit.php' => $entry],
            ['wp-content/mu-plugins/legit.php' => $entry],
        );

        $this->assertSame([], $findings);
    }

    public function testDoesNotFlagFilesOutsideMuPlugins(): void
    {
        $detector = new MuPluginsDetector();

        $findings = $detector->detect(['wp-content/plugins/foo/bar.php' => $this->entry()], []);

        $this->assertSame([], $findings);
    }
}
