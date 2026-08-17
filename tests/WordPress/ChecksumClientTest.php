<?php
// tests/WordPress/ChecksumClientTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\WordPress\ChecksumClient;
use PHPUnit\Framework\TestCase;

final class ChecksumClientTest extends TestCase
{
    public function testGetCoreChecksumsReturnsMapFromResponse(): void
    {
        $capturedUrl = null;
        $client = new ChecksumClient(function (string $url) use (&$capturedUrl): array {
            $capturedUrl = $url;
            return ['checksums' => ['wp-admin/index.php' => 'abc123']];
        });

        $result = $client->getCoreChecksums('6.5.2');

        $this->assertSame(['wp-admin/index.php' => 'abc123'], $result);
        $this->assertStringContainsString('version=6.5.2', $capturedUrl);
    }

    public function testGetCoreChecksumsReturnsNullWhenHttpCallFails(): void
    {
        $client = new ChecksumClient(fn (string $url): ?array => null);

        $this->assertNull($client->getCoreChecksums('6.5.2'));
    }

    public function testGetCoreChecksumsReturnsNullWhenShapeIsUnexpected(): void
    {
        $client = new ChecksumClient(fn (string $url): array => ['unexpected' => true]);

        $this->assertNull($client->getCoreChecksums('6.5.2'));
    }
}
