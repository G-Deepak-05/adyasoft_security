<?php
// dashboard/src/Findings/FindingsRepository.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Findings;

final class FindingsRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function search(array $filters, int $page, int $perPage): array
    {
        [$whereSql, $params] = $this->buildWhere($filters);

        $countStmt = $this->pdo->prepare("SELECT COUNT(*) FROM findings {$whereSql}");
        $countStmt->execute($params);
        $total = (int) $countStmt->fetchColumn();

        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $offset = ($page - 1) * $perPage;

        $severityOrder = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
        $sql = "SELECT * FROM findings {$whereSql} ORDER BY {$severityOrder} ASC, scanned_at DESC LIMIT {$perPage} OFFSET {$offset}";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        $rows = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $row['details'] = json_decode($row['details'], true);
            $rows[] = $row;
        }

        return ['rows' => $rows, 'total' => $total];
    }

    private function buildWhere(array $filters): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['severities'])) {
            $placeholders = implode(',', array_fill(0, count($filters['severities']), '?'));
            $where[] = "severity IN ({$placeholders})";
            array_push($params, ...$filters['severities']);
        }

        if (!empty($filters['accountId'])) {
            $where[] = 'account_id = ?';
            $params[] = $filters['accountId'];
        }

        if (!empty($filters['siteId'])) {
            $where[] = 'site_id = ?';
            $params[] = $filters['siteId'];
        }

        if (!empty($filters['types'])) {
            $placeholders = implode(',', array_fill(0, count($filters['types']), '?'));
            $where[] = "finding_type IN ({$placeholders})";
            array_push($params, ...$filters['types']);
        }

        if (!empty($filters['from'])) {
            $where[] = 'scanned_at >= ?';
            $params[] = $filters['from'];
        }

        if (!empty($filters['to'])) {
            $where[] = 'scanned_at <= ?';
            $params[] = $filters['to'];
        }

        $whereSql = $where === [] ? '' : 'WHERE ' . implode(' AND ', $where);

        return [$whereSql, $params];
    }
}
