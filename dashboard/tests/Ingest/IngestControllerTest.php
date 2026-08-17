<?php
// dashboard/tests/Ingest/IngestControllerTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Ingest;

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Ingest\IngestController;
use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;
use AdyaSoft\Dashboard\Tests\Fixtures\SqliteDashboardSchema;
use PHPUnit\Framework\TestCase;

final class IngestControllerTest extends TestCase
{
    private function validBody(): string
    {
        return json_encode([
            'meta' => [
                'site_id' => 'abc123def456',
                'site_label' => 'example.com',
                'scan_id' => 'scan-1',
                'scanned_at' => '2026-08-17T10:00:00+00:00',
            ],
            'findings' => [
                [
                    'subject' => 'a.php',
                    'severity' => 'HIGH',
                    'composite_score' => 50,
                    'findings' => [['type' => 'file_new', 'details' => []]],
                ],
            ],
        ]);
    }

    private function makeController(\PDO $pdo): IngestController
    {
        return new IngestController(
            new ApiKeyAuthenticator($pdo),
            new IngestPayloadValidator(),
            new FindingsIngester($pdo),
        );
    }

    public function testValidRequestReturns200AndInsertsRows(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", $this->validBody());

        $this->assertSame(200, $result['status']);
        $decoded = json_decode($result['body'], true);
        $this->assertSame('ok', $decoded['status']);
        $this->assertSame(1, $decoded['rows_inserted']);
    }

    public function testMissingApiKeyReturns401(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $controller = $this->makeController($pdo);

        $result = $controller->handle(null, $this->validBody());

        $this->assertSame(401, $result['status']);
    }

    public function testInvalidApiKeyReturns401(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        (new AccountRepository($pdo))->create('client-a');
        $controller = $this->makeController($pdo);

        $result = $controller->handle('Bearer ' . bin2hex(random_bytes(32)), $this->validBody());

        $this->assertSame(401, $result['status']);
    }

    public function testMalformedJsonBodyReturns400(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", '{not valid json');

        $this->assertSame(400, $result['status']);
    }

    public function testPayloadFailingValidationReturns400(): void
    {
        $pdo = SqliteDashboardSchema::createInMemoryDb();
        $apiKey = (new AccountRepository($pdo))->create('client-a')['api_key'];
        $controller = $this->makeController($pdo);

        $result = $controller->handle("Bearer {$apiKey}", json_encode(['meta' => []]));

        $this->assertSame(400, $result['status']);
        $decoded = json_decode($result['body'], true);
        $this->assertNotEmpty($decoded['errors']);
    }
}
