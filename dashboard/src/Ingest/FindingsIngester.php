<?php
// dashboard/src/Ingest/FindingsIngester.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

final class FindingsIngester
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function ingest(int $accountId, array $payload): int
    {
        $siteId = $payload['meta']['site_id'];
        $siteLabel = $payload['meta']['site_label'] ?? null;
        $scanId = $payload['meta']['scan_id'];
        $scannedAt = $payload['meta']['scanned_at'];
        $ingestedAt = date('Y-m-d H:i:s');

        $this->pdo->beginTransaction();

        try {
            $delete = $this->pdo->prepare('DELETE FROM findings WHERE account_id = ? AND scan_id = ?');
            $delete->execute([$accountId, $scanId]);

            $insert = $this->pdo->prepare(
                'INSERT INTO findings
                    (account_id, site_id, site_label, scan_id, subject, severity, composite_score, finding_type, details, scanned_at, ingested_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $rowsInserted = 0;
            foreach ($this->collapseDuplicateFindings($payload['findings']) as $row) {
                $insert->execute([
                    $accountId,
                    $siteId,
                    $siteLabel,
                    $scanId,
                    $row['subject'],
                    $row['severity'],
                    $row['composite_score'],
                    $row['finding_type'],
                    json_encode($row['details'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
                    $scannedAt,
                    $ingestedAt,
                ]);
                $rowsInserted++;
            }

            $this->pdo->commit();

            return $rowsInserted;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Flatten the grouped payload into one row per (subject, finding_type) pair.
     *
     * Some detectors legitimately emit several individual findings of the SAME
     * finding_type under the SAME subject in a single scan (e.g. HtaccessDetector
     * emits one htaccess_external_redirect per malicious redirect target, all
     * grouped by RiskScorer under the fixed subject '.htaccess'). Inserting those
     * as separate rows would violate the findings table's
     * UNIQUE(account_id, scan_id, subject, finding_type) index and roll back the
     * entire scan's ingestion.
     *
     * Duplicates are therefore merged into the first occurrence rather than
     * dropped: the surviving row's details become
     * {"details": [<first>, <second>, ...]} so every original details payload
     * remains recoverable. A row with exactly one occurrence keeps its original
     * details object unchanged.
     */
    private function collapseDuplicateFindings(array $groups): array
    {
        $rows = [];

        foreach ($groups as $group) {
            $subject = (string) $group['subject'];

            foreach ($group['findings'] as $individual) {
                $type = $individual['type'];
                $details = $individual['details'] ?? [];
                $key = $subject . "\0" . $type;

                if (!isset($rows[$key])) {
                    $rows[$key] = [
                        'subject' => $subject,
                        'severity' => $group['severity'],
                        'composite_score' => $group['composite_score'],
                        'finding_type' => $type,
                        'details' => [$details],
                    ];
                    continue;
                }

                $rows[$key]['details'][] = $details;
            }
        }

        foreach ($rows as $key => $row) {
            $rows[$key]['details'] = count($row['details']) === 1
                ? $row['details'][0]
                : ['details' => array_values($row['details'])];
        }

        return array_values($rows);
    }
}
