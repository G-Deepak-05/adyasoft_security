<?php
// dashboard/src/Ingest/IngestController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;

final class IngestController
{
    public function __construct(
        private readonly ApiKeyAuthenticator $authenticator,
        private readonly IngestPayloadValidator $validator,
        private readonly FindingsIngester $ingester,
    ) {
    }

    public function handle(?string $authorizationHeader, string $rawBody): array
    {
        $accountId = $this->authenticator->authenticate($authorizationHeader);
        if ($accountId === null) {
            return $this->jsonResponse(401, ['status' => 'error', 'message' => 'invalid or missing API key']);
        }

        $payload = json_decode($rawBody, true);
        if (!is_array($payload)) {
            return $this->jsonResponse(400, ['status' => 'error', 'message' => 'body must be valid JSON']);
        }

        $validation = $this->validator->validate($payload);
        if (!$validation['valid']) {
            return $this->jsonResponse(400, ['status' => 'error', 'errors' => $validation['errors']]);
        }

        $rowsInserted = $this->ingester->ingest($accountId, $payload);

        return $this->jsonResponse(200, ['status' => 'ok', 'rows_inserted' => $rowsInserted]);
    }

    private function jsonResponse(int $status, array $body): array
    {
        return ['status' => $status, 'body' => json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)];
    }
}
