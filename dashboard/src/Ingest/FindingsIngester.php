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
            foreach ($payload['findings'] as $group) {
                foreach ($group['findings'] as $individual) {
                    $insert->execute([
                        $accountId,
                        $siteId,
                        $siteLabel,
                        $scanId,
                        (string) $group['subject'],
                        $group['severity'],
                        $group['composite_score'],
                        $individual['type'],
                        json_encode($individual['details'] ?? [], JSON_UNESCAPED_SLASHES),
                        $scannedAt,
                        $ingestedAt,
                    ]);
                    $rowsInserted++;
                }
            }

            $this->pdo->commit();

            return $rowsInserted;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
}
