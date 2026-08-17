<?php
// dashboard/src/Findings/FindingsPageController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Findings;

final class FindingsPageController
{
    private const PER_PAGE = 50;
    private const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

    public function __construct(private readonly FindingsRepository $repository)
    {
    }

    public function buildViewModel(array $queryParams): array
    {
        $severities = isset($queryParams['severity']) && is_array($queryParams['severity'])
            ? array_values(array_intersect($queryParams['severity'], self::VALID_SEVERITIES))
            : [];

        $accountId = isset($queryParams['account_id']) && $queryParams['account_id'] !== ''
            ? (int) $queryParams['account_id']
            : null;

        $siteId = isset($queryParams['site_id']) && $queryParams['site_id'] !== ''
            ? (string) $queryParams['site_id']
            : null;

        // Finding types arrive either as a repeated `type[]` param or, from the
        // findings page's free-text control, as a comma-separated `type_filter`
        // string. There is no fixed enum of types (the scanner gains detectors
        // over time), so neither shape is validated against a whitelist.
        $types = [];
        if (isset($queryParams['type']) && is_array($queryParams['type'])) {
            $types = array_values($queryParams['type']);
        } elseif (isset($queryParams['type_filter']) && is_string($queryParams['type_filter'])) {
            $types = array_values(array_filter(
                array_map('trim', explode(',', $queryParams['type_filter'])),
                static fn (string $type): bool => $type !== '',
            ));
        }

        $from = isset($queryParams['from']) && $queryParams['from'] !== '' ? (string) $queryParams['from'] : null;
        $to = isset($queryParams['to']) && $queryParams['to'] !== '' ? (string) $queryParams['to'] : null;
        $page = isset($queryParams['page']) ? max(1, (int) $queryParams['page']) : 1;

        $result = $this->repository->search(
            [
                'severities' => $severities,
                'accountId' => $accountId,
                'siteId' => $siteId,
                'types' => $types,
                'from' => $from,
                'to' => $to,
            ],
            $page,
            self::PER_PAGE,
        );

        return [
            'rows' => $result['rows'],
            'total' => $result['total'],
            'page' => $page,
            'perPage' => self::PER_PAGE,
            'totalPages' => (int) ceil($result['total'] / self::PER_PAGE),
            'filters' => [
                'severity' => $severities,
                'account_id' => $accountId,
                'site_id' => $siteId,
                'type' => $types,
                'from' => $from,
                'to' => $to,
            ],
        ];
    }
}
