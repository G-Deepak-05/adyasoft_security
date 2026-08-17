<?php
// tests/Reporting/ReportBuilderTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\ReportBuilder;
use PHPUnit\Framework\TestCase;

final class ReportBuilderTest extends TestCase
{
    private function meta(): array
    {
        return ['site_id' => 'abc123', 'site_path' => '/home/user/public_html', 'scan_id' => 'scan-1', 'mode' => 'audit', 'scanned_at' => '2026-08-17T00:00:00+00:00'];
    }

    public function testBuildIncludesMetaAndSortsFindingsBySeverityDescending(): void
    {
        $builder = new ReportBuilder();

        $scored = [
            ['subject' => 'low-thing', 'findings' => [['type' => 'file_new']], 'composite_score' => 10, 'severity' => 'LOW'],
            ['subject' => 'critical-thing', 'findings' => [['type' => 'file_in_uploads_is_php']], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'high-thing', 'findings' => [['type' => 'core_file_checksum_mismatch']], 'composite_score' => 50, 'severity' => 'HIGH'],
        ];

        $report = $builder->build($this->meta(), $scored);

        $this->assertSame('abc123', $report['meta']['site_id']);
        $severities = array_column($report['findings'], 'severity');
        $this->assertSame(['CRITICAL', 'HIGH', 'LOW'], $severities);
    }

    public function testBuildComputesSummaryCountsBySeverity(): void
    {
        $builder = new ReportBuilder();
        $scored = [
            ['subject' => 'a', 'findings' => [], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'b', 'findings' => [], 'composite_score' => 90, 'severity' => 'CRITICAL'],
            ['subject' => 'c', 'findings' => [], 'composite_score' => 10, 'severity' => 'LOW'],
        ];

        $report = $builder->build($this->meta(), $scored);

        $this->assertSame(3, $report['summary']['total_findings']);
        $this->assertSame(2, $report['summary']['by_severity']['CRITICAL']);
        $this->assertSame(0, $report['summary']['by_severity']['HIGH']);
        $this->assertSame(0, $report['summary']['by_severity']['MEDIUM']);
        $this->assertSame(1, $report['summary']['by_severity']['LOW']);
    }

    public function testToJsonProducesValidJsonRoundTrippingTheReport(): void
    {
        $builder = new ReportBuilder();
        $report = $builder->build($this->meta(), []);

        $json = $builder->toJson($report);

        $this->assertSame($report, json_decode($json, true));
    }

    public function testToHumanReadableIncludesSiteIdAndOneLinePerFinding(): void
    {
        $builder = new ReportBuilder();
        $scored = [
            ['subject' => 'wp-content/uploads/shell.php', 'findings' => [['type' => 'file_new'], ['type' => 'file_in_uploads_is_php']], 'composite_score' => 60, 'severity' => 'HIGH'],
        ];
        $report = $builder->build($this->meta(), $scored);

        $text = $builder->toHumanReadable($report);

        $this->assertStringContainsString('abc123', $text);
        $this->assertStringContainsString('[HIGH] wp-content/uploads/shell.php (score 60): file_new, file_in_uploads_is_php', $text);
    }
}
