<?php
// tests/Reporting/FindingsPusherTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\FindingsPusher;
use PHPUnit\Framework\TestCase;

final class FindingsPusherTest extends TestCase
{
    private function report(): array
    {
        return [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_path' => '/home/user/public_html',
                'scan_id' => 'abc123def456-cheap-20260817-100000',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'summary' => ['total_findings' => 1, 'by_severity' => ['CRITICAL' => 1, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0]],
            'findings' => [
                ['subject' => 'a.php', 'severity' => 'CRITICAL', 'composite_score' => 90, 'findings' => [['type' => 'file_new', 'details' => []]]],
            ],
        ];
    }

    public function testPushSendsMetaAndFindingsToTheInjectedCallable(): void
    {
        $captured = null;
        $pusher = new FindingsPusher(
            function (string $url, array $payload, string $apiKey) use (&$captured): bool {
                $captured = compact('url', 'payload', 'apiKey');
                return true;
            },
            'https://dashboard.example.com/ingest.php',
            'test-api-key',
        );

        $result = $pusher->push($this->report());

        $this->assertTrue($result);
        $this->assertSame('https://dashboard.example.com/ingest.php', $captured['url']);
        $this->assertSame('test-api-key', $captured['apiKey']);
        $this->assertSame('abc123def456', $captured['payload']['meta']['site_id']);
        $this->assertSame('/home/user/public_html', $captured['payload']['meta']['site_label']);
        $this->assertSame('abc123def456-cheap-20260817-100000', $captured['payload']['meta']['scan_id']);
        $this->assertSame($this->report()['findings'], $captured['payload']['findings']);
    }

    public function testPushReturnsFalseWhenCallableFails(): void
    {
        $pusher = new FindingsPusher(
            fn (string $url, array $payload, string $apiKey): bool => false,
            'https://dashboard.example.com/ingest.php',
            'test-api-key',
        );

        $this->assertFalse($pusher->push($this->report()));
    }
}
