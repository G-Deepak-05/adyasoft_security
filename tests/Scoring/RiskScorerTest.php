<?php
// tests/Scoring/RiskScorerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Scoring;

use AdyaSoft\Security\Scoring\RiskScorer;
use PHPUnit\Framework\TestCase;

final class RiskScorerTest extends TestCase
{
    private function weights(): array
    {
        return [
            'file_new' => 20,
            'file_in_uploads_is_php' => 40,
            'entropy_obfuscation_pattern' => 30,
            'user_not_in_known_good_roster' => 50,
        ];
    }

    private function thresholds(): array
    {
        return ['CRITICAL' => 70, 'HIGH' => 45, 'MEDIUM' => 20, 'LOW' => 0];
    }

    public function testCombinesMultipleSignalsForTheSameFileIntoOneCompositeScore(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $findings = [
            ['type' => 'file_new', 'path' => 'wp-content/uploads/shell.php'],
            ['type' => 'file_in_uploads_is_php', 'path' => 'wp-content/uploads/shell.php'],
            ['type' => 'entropy_obfuscation_pattern', 'path' => 'wp-content/uploads/shell.php'],
        ];

        $scored = $scorer->score($findings);

        $this->assertCount(1, $scored);
        $this->assertSame('wp-content/uploads/shell.php', $scored[0]['subject']);
        $this->assertSame(90, $scored[0]['composite_score']); // 20 + 40 + 30
        $this->assertSame('CRITICAL', $scored[0]['severity']);
        $this->assertCount(3, $scored[0]['findings']);
    }

    public function testSeparatesDifferentSubjectsIntoDifferentScoredItems(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $findings = [
            ['type' => 'file_new', 'path' => 'a.php'],
            ['type' => 'user_not_in_known_good_roster', 'user_login' => 'rogue'],
        ];

        $scored = $scorer->score($findings);

        $subjects = array_column($scored, 'subject');
        sort($subjects);
        $this->assertSame(['a.php', 'rogue'], $subjects);
    }

    public function testAssignsLowSeverityWhenBelowAllHigherThresholds(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $scored = $scorer->score([['type' => 'file_new', 'path' => 'a.php']]);

        $this->assertSame(20, $scored[0]['composite_score']);
        $this->assertSame('MEDIUM', $scored[0]['severity']);
    }

    public function testUnknownSignalTypeContributesZeroWeightButIsStillIncluded(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $scored = $scorer->score([['type' => 'some_future_signal', 'path' => 'a.php']]);

        $this->assertSame(0, $scored[0]['composite_score']);
        $this->assertSame('LOW', $scored[0]['severity']);
    }

    public function testDoesNotCollideCrossDomainNumericSubjects(): void
    {
        $scorer = new RiskScorer($this->weights(), $this->thresholds());

        $findings = [
            ['type' => 'user_not_in_known_good_roster', 'user_login' => '1'],
            ['type' => 'page_unexpected_author', 'page_id' => 1],
        ];

        $scored = $scorer->score($findings);

        $this->assertCount(2, $scored);
        $this->assertCount(1, $scored[0]['findings']);
        $this->assertCount(1, $scored[1]['findings']);
        $this->assertNotSame($scored[0]['subject'], $scored[1]['subject']);
    }
}
