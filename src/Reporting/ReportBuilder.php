<?php
// src/Reporting/ReportBuilder.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class ReportBuilder
{
    private const SEVERITY_ORDER = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];

    public function build(array $meta, array $scoredFindings): array
    {
        usort($scoredFindings, static function (array $a, array $b): int {
            $orderA = self::SEVERITY_ORDER[$a['severity']] ?? 99;
            $orderB = self::SEVERITY_ORDER[$b['severity']] ?? 99;
            return $orderA <=> $orderB ?: $a['subject'] <=> $b['subject'];
        });

        $bySeverity = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
        foreach ($scoredFindings as $item) {
            $bySeverity[$item['severity']] = ($bySeverity[$item['severity']] ?? 0) + 1;
        }

        return [
            'meta' => $meta,
            'summary' => [
                'total_findings' => count($scoredFindings),
                'by_severity' => $bySeverity,
            ],
            'findings' => $scoredFindings,
        ];
    }

    public function toJson(array $report): string
    {
        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function toHumanReadable(array $report): string
    {
        $lines = [];
        $lines[] = sprintf(
            'Scan report — site %s (%s) — scan %s — %s — mode: %s',
            $report['meta']['site_id'],
            $report['meta']['site_path'],
            $report['meta']['scan_id'],
            $report['meta']['scanned_at'],
            $report['meta']['mode'],
        );
        $lines[] = sprintf(
            'Total findings: %d (CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)',
            $report['summary']['total_findings'],
            $report['summary']['by_severity']['CRITICAL'],
            $report['summary']['by_severity']['HIGH'],
            $report['summary']['by_severity']['MEDIUM'],
            $report['summary']['by_severity']['LOW'],
        );

        $degraded = $report['meta']['degraded_checks'] ?? [];
        if ($degraded !== []) {
            $lines[] = sprintf('Degraded checks: %d', count($degraded));
            foreach ($degraded as $reason) {
                $lines[] = '  - ' . $reason;
            }
        }

        $lines[] = '';

        foreach ($report['findings'] as $item) {
            $types = implode(', ', array_column($item['findings'], 'type'));
            $lines[] = sprintf('[%s] %s (score %d): %s', $item['severity'], $item['subject'], $item['composite_score'], $types);
        }

        return implode("\n", $lines);
    }
}
