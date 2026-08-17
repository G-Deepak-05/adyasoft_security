<?php
// tests/Reporting/MailerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\Mailer;
use PHPUnit\Framework\TestCase;

final class MailerTest extends TestCase
{
    private function mailConfig(): array
    {
        return ['from' => 'scanner@example.com', 'to' => ['ops@example.com'], 'alert_on_bands' => ['CRITICAL', 'HIGH'], 'digest_hour_utc' => 6];
    }

    private function reportWithSeverities(array $severities): array
    {
        $findings = [];
        foreach ($severities as $severity) {
            $findings[] = ['subject' => 'x', 'findings' => [], 'composite_score' => 0, 'severity' => $severity];
        }
        return ['meta' => ['site_id' => 'site-a'], 'summary' => [], 'findings' => $findings];
    }

    public function testSendsAlertWhenCriticalFindingPresent(): void
    {
        $sent = null;
        $mailer = new Mailer(function (string $to, string $subject, string $body) use (&$sent): bool {
            $sent = compact('to', 'subject', 'body');
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities(['CRITICAL']), 'body text');

        $this->assertTrue($result);
        $this->assertSame('ops@example.com', $sent['to']);
        $this->assertStringContainsString('site-a', $sent['subject']);
    }

    public function testDoesNotSendWhenOnlyLowAndMediumFindingsPresent(): void
    {
        $called = false;
        $mailer = new Mailer(function () use (&$called): bool {
            $called = true;
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities(['MEDIUM', 'LOW']), 'body text');

        $this->assertFalse($result);
        $this->assertFalse($called);
    }

    public function testDoesNotSendWhenNoFindingsAtAll(): void
    {
        $called = false;
        $mailer = new Mailer(function () use (&$called): bool {
            $called = true;
            return true;
        }, $this->mailConfig());

        $result = $mailer->sendAlertIfNeeded($this->reportWithSeverities([]), 'body text');

        $this->assertFalse($result);
        $this->assertFalse($called);
    }
}
