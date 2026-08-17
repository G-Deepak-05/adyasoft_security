<?php
// src/Reporting/Mailer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Reporting;

final class Mailer
{
    /** @param callable(string, string, string): bool $sendMail */
    public function __construct(
        private readonly mixed $sendMail,
        private readonly array $mailConfig,
    ) {
    }

    public function sendAlertIfNeeded(array $report, string $humanReadableBody): bool
    {
        $alertBands = $this->mailConfig['alert_on_bands'];
        $highestBand = null;

        foreach ($report['findings'] as $item) {
            if (in_array($item['severity'], $alertBands, true)) {
                $highestBand = $item['severity'];
                break; // findings are pre-sorted by severity descending (ReportBuilder)
            }
        }

        if ($highestBand === null) {
            return false;
        }

        $subject = sprintf('[%s] Security finding on %s', $highestBand, $report['meta']['site_id']);

        foreach ($this->mailConfig['to'] as $recipient) {
            ($this->sendMail)($recipient, $subject, $humanReadableBody);
        }

        return true;
    }
}
