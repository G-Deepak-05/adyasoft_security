<?php
// tests/Detectors/HtaccessDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\HtaccessDetector;
use PHPUnit\Framework\TestCase;

final class HtaccessDetectorTest extends TestCase
{
    public function testNoFindingsWhenContentsUnchanged(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "RewriteEngine On\n";

        $findings = $detector->detect($contents, $contents);

        $this->assertSame([], $findings);
    }

    public function testFlagsDiffWhenContentsChange(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);

        $findings = $detector->detect("RewriteEngine On\nNewLine\n", "RewriteEngine On\n");

        $this->assertSame('htaccess_diff', $findings[0]['type']);
    }

    public function testFlagsExternalRedirectToUnknownDomain(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "RewriteRule ^bad$ http://evil-spam.example/landing [R=301,L]\n";

        $findings = $detector->detect($contents, $contents);

        $types = array_column($findings, 'type');
        $this->assertContains('htaccess_external_redirect', $types);
        $external = array_values(array_filter($findings, fn ($f) => $f['type'] === 'htaccess_external_redirect'))[0];
        $this->assertStringContainsString('evil-spam.example', $external['details']['target']);
    }

    public function testFlagsStatusCodedRedirectToExternalDomain(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "Redirect 301 /old http://evil-spam.example/phish\n";

        $findings = $detector->detect($contents, $contents);

        $types = array_column($findings, 'type');
        $this->assertContains('htaccess_external_redirect', $types);
        $external = array_values(array_filter($findings, fn ($f) => $f['type'] === 'htaccess_external_redirect'))[0];
        $this->assertStringContainsString('evil-spam.example', $external['details']['target']);
    }

    public function testDoesNotFlagRedirectToKnownSiteDomain(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);
        $contents = "Redirect 301 /old https://mysite.com/new\n";

        $findings = $detector->detect($contents, $contents);

        $this->assertSame([], $findings);
    }

    public function testFlagsDiffWhenFileAppearsFromNoBaseline(): void
    {
        $detector = new HtaccessDetector(['mysite.com']);

        $findings = $detector->detect("RewriteEngine On\n", null);

        $this->assertSame('htaccess_diff', $findings[0]['type']);
    }
}
