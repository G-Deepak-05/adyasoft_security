<?php
// dashboard/tests/Ingest/IngestPayloadValidatorTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Ingest;

use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;
use PHPUnit\Framework\TestCase;

final class IngestPayloadValidatorTest extends TestCase
{
    private function validPayload(): array
    {
        return [
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => 'abc123def456-cheap-20260817-100000',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => 'wp-content/uploads/shell.php',
                    'severity' => 'CRITICAL',
                    'composite_score' => 90,
                    'findings' => [
                        ['type' => 'file_new', 'details' => ['size' => 100]],
                        ['type' => 'file_in_uploads_is_php', 'details' => []],
                    ],
                ],
            ],
        ];
    }

    public function testAcceptsAWellFormedPayload(): void
    {
        $validator = new IngestPayloadValidator();

        $result = $validator->validate($this->validPayload());

        $this->assertTrue($result['valid']);
        $this->assertSame([], $result['errors']);
    }

    public function testRejectsMissingMeta(): void
    {
        $payload = $this->validPayload();
        unset($payload['meta']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertNotEmpty($result['errors']);
    }

    public function testRejectsMetaMissingRequiredKey(): void
    {
        $payload = $this->validPayload();
        unset($payload['meta']['scan_id']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('scan_id', $result['errors'][0]);
    }

    public function testRejectsFindingsEntryMissingSeverity(): void
    {
        $payload = $this->validPayload();
        unset($payload['findings'][0]['severity']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
    }

    public function testRejectsIndividualFindingMissingType(): void
    {
        $payload = $this->validPayload();
        unset($payload['findings'][0]['findings'][0]['type']);

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
    }

    public function testRejectsAnUnknownSeverityBand(): void
    {
        $payload = $this->validPayload();
        $payload['findings'][0]['severity'] = 'PWNED';

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('findings[0].severity', $result['errors'][0]);
        $this->assertStringContainsString('CRITICAL', $result['errors'][0]);
    }

    public function testRejectsANonNumericCompositeScore(): void
    {
        $payload = $this->validPayload();
        $payload['findings'][0]['composite_score'] = 'not-a-number';

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertFalse($result['valid']);
        $this->assertStringContainsString('findings[0].composite_score', $result['errors'][0]);
    }

    public function testAcceptsEveryValidSeverityBand(): void
    {
        foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $severity) {
            $payload = $this->validPayload();
            $payload['findings'][0]['severity'] = $severity;

            $result = (new IngestPayloadValidator())->validate($payload);

            $this->assertTrue($result['valid'], "severity {$severity} must be accepted");
        }
    }

    public function testAcceptsEmptyFindingsArray(): void
    {
        $payload = $this->validPayload();
        $payload['findings'] = [];

        $result = (new IngestPayloadValidator())->validate($payload);

        $this->assertTrue($result['valid']);
    }
}
