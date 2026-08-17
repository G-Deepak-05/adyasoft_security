<?php
// bin/run.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Security\Discovery\ManifestStore;
use AdyaSoft\Security\Discovery\SiteDiscoverer;
use AdyaSoft\Security\Reporting\DigestQueue;
use AdyaSoft\Security\Reporting\FindingsPusher;
use AdyaSoft\Security\Reporting\Mailer;
use AdyaSoft\Security\Reporting\ReportBuilder;
use AdyaSoft\Security\Scanner;
use AdyaSoft\Security\Support\ConfigLoader;
use AdyaSoft\Security\Support\Logger;

$options = getopt('', ['checks:', 'account-home:']);
$tier = $options['checks'] ?? 'all';
$accountHome = $options['account-home'] ?? dirname(__DIR__, 2); // default: parent of security-scanner/

if (!in_array($tier, ['cheap', 'expensive', 'all'], true)) {
    fwrite(STDERR, "Invalid --checks value: {$tier}. Use cheap, expensive, or all.\n");
    exit(1);
}

$rootDir = dirname(__DIR__);
$dataDir = "{$rootDir}/data";

$scoringConfig = ConfigLoader::load("{$rootDir}/config/scoring.php");
$mailConfig = ConfigLoader::load("{$rootDir}/config/mail.php");
$sitesConfig = ConfigLoader::load("{$rootDir}/config/sites.php");
$dashboardConfig = ConfigLoader::load("{$rootDir}/config/dashboard.php");

$logger = new Logger("{$dataDir}/run.log");
$logger->info('discovery started', ['account_home' => $accountHome]);

$discoverer = new SiteDiscoverer($accountHome);
$discovered = $discoverer->discover();

$manifestStore = new ManifestStore("{$dataDir}/manifest.json");
$manifest = $manifestStore->reconcile($manifestStore->load(), $discovered);
$manifestStore->save($manifest);

$mailer = new Mailer(
    static function (string $to, string $subject, string $body) use ($mailConfig): bool {
        return mail($to, $subject, $body, "From: {$mailConfig['from']}\r\n");
    },
    $mailConfig,
);
$findingsPusher = new FindingsPusher(
    static function (string $url, array $payload, string $apiKey): bool {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAuthorization: Bearer {$apiKey}\r\n",
                'content' => json_encode($payload, JSON_UNESCAPED_SLASHES),
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            return false;
        }
        $statusLine = $http_response_header[0] ?? '';
        return (bool) preg_match('/\s200\s/', $statusLine);
    },
    $dashboardConfig['endpoint'],
    $dashboardConfig['api_key'],
);
$digestQueue = new DigestQueue("{$dataDir}/digest-queue.jsonl");
$reportBuilder = new ReportBuilder();
$scanner = new Scanner($dataDir, $scoringConfig, $sitesConfig);

$tiersToRun = $tier === 'all' ? ['cheap', 'expensive'] : [$tier];

$failureCount = 0;
$scannedCount = 0;

foreach ($manifest as $siteId => $entry) {
    if ($entry['status'] !== 'active') {
        continue;
    }

    foreach ($tiersToRun as $runTier) {
        try {
            $report = $scanner->scanSite($entry['path'], $siteId, $runTier);
            $humanReadable = $reportBuilder->toHumanReadable($report);

            $alerted = $mailer->sendAlertIfNeeded($report, $humanReadable);
            if (!$alerted) {
                $digestQueue->append([
                    'site_id' => $siteId,
                    'scanned_at' => $report['meta']['scanned_at'],
                    'total_findings' => $report['summary']['total_findings'],
                    'degraded' => count($report['meta']['degraded_checks'] ?? []),
                ]);
            }

            $scannedCount++;

            if (!$findingsPusher->push($report)) {
                $logger->warning('failed to push findings to dashboard', ['site_id' => $siteId, 'tier' => $runTier]);
            }
        } catch (\Throwable $e) {
            $logger->error('scan failed for site; continuing with remaining sites', [
                'site_id' => $siteId,
                'tier' => $runTier,
                'error' => $e->getMessage(),
            ]);
            $failureCount++;
            continue;
        }
    }
}

if ((int) gmdate('G') === (int) $mailConfig['digest_hour_utc']) {
    $entries = $digestQueue->flush();
    if ($entries !== []) {
        $body = "Daily digest — clean/no-alert scans:\n\n" . implode("\n", array_map(
            static fn (array $e) => sprintf(
                '%s: %d findings at %s%s',
                $e['site_id'],
                $e['total_findings'],
                $e['scanned_at'],
                ($e['degraded'] ?? 0) > 0 ? sprintf(' (%d degraded check(s))', $e['degraded']) : '',
            ),
            $entries,
        ));
        foreach ($mailConfig['to'] as $recipient) {
            mail($recipient, 'Security scanner daily digest', $body, "From: {$mailConfig['from']}\r\n");
        }
    }
}

$logger->info('run complete', ['sites_scanned' => $scannedCount, 'failures' => $failureCount]);

if ($failureCount > 0) {
    fwrite(STDERR, "{$failureCount} site/tier scan(s) failed — see data/run.log for details.\n");
    exit(1);
}
