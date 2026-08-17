<?php
// src/Reporting/FindingsPusher.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class FindingsPusher
{
    /** @param callable(string, array, string): bool $httpPost */
    public function __construct(
        private readonly mixed $httpPost,
        private readonly string $endpoint,
        private readonly string $apiKey,
    ) {
    }

    public function push(array $report): bool
    {
        $payload = [
            'meta' => [
                'site_id' => $report['meta']['site_id'],
                'site_label' => $report['meta']['site_path'] ?? null,
                'scan_id' => $report['meta']['scan_id'],
                'scanned_at' => $report['meta']['scanned_at'],
            ],
            'findings' => $report['findings'],
        ];

        return ($this->httpPost)($this->endpoint, $payload, $this->apiKey);
    }
}
