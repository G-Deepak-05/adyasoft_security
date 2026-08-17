<?php
// src/Scoring/RiskScorer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Scoring;

final class RiskScorer
{
    public function __construct(
        private readonly array $weights,
        private readonly array $severityThresholds,
    ) {
    }

    public function score(array $findings): array
    {
        $grouped = [];

        foreach ($findings as $finding) {
            $subject = $finding['path'] ?? $finding['user_login'] ?? $finding['page_id'] ?? '.htaccess';
            $kind = isset($finding['path']) ? 'path' : (isset($finding['user_login']) ? 'user' : (isset($finding['page_id']) ? 'page' : 'htaccess'));
            $groupKey = $kind . ':' . $subject;

            if (!isset($grouped[$groupKey])) {
                $grouped[$groupKey] = ['subject' => $subject, 'findings' => []];
            }
            $grouped[$groupKey]['findings'][] = $finding;
        }

        $scored = [];
        foreach ($grouped as $group) {
            $compositeScore = 0;
            foreach ($group['findings'] as $finding) {
                $compositeScore += $this->weights[$finding['type']] ?? 0;
            }

            $scored[] = [
                'subject' => $group['subject'],
                'findings' => $group['findings'],
                'composite_score' => $compositeScore,
                'severity' => $this->severityFor($compositeScore),
            ];
        }

        return $scored;
    }

    private function severityFor(int $compositeScore): string
    {
        $thresholds = $this->severityThresholds;
        arsort($thresholds);

        foreach ($thresholds as $band => $threshold) {
            if ($compositeScore >= $threshold) {
                return $band;
            }
        }

        return 'LOW';
    }
}
