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

        $types = isset($queryParams['type']) && is_array($queryParams['type'])
            ? array_values($queryParams['type'])
            : [];

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
