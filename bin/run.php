<?php
// bin/run.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Security\Discovery\ManifestStore;
use AdyaSoft\Security\Discovery\SiteDiscoverer;
use AdyaSoft\Security\Reporting\DigestQueue;
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

$logger = new Logger("{$dataDir}/run.log");
$logger->info('discovery started', ['account_home' => $accountHome]);

$discoverer = new SiteDiscoverer($accountHome);
$discovered = $discoverer->discover();

$manifestStore = new ManifestStore("{$dataDir}/manifest.json");
$manifest = $manifestStore->reconcile($manifestStore->load(), $discovered);
$manifestStore->save($manifest);

$mailer = new Mailer(
    static function (string $to, string $subject, string $body): bool {
        return mail($to, $subject, $body);
    },
    $mailConfig,
);
$digestQueue = new DigestQueue("{$dataDir}/digest-queue.jsonl");
$reportBuilder = new ReportBuilder();
$scanner = new Scanner($dataDir, $scoringConfig, $mailConfig, $sitesConfig);

$tiersToRun = $tier === 'all' ? ['cheap', 'expensive'] : [$tier];

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
                ]);
            }
        } catch (\Throwable $e) {
            $logger->error('scan failed for site; continuing with remaining sites', [
                'site_id' => $siteId,
                'tier' => $runTier,
                'error' => $e->getMessage(),
            ]);
            continue;
        }
    }
}

if ((int) date('G') === (int) $mailConfig['digest_hour_utc']) {
    $entries = $digestQueue->flush();
    if ($entries !== []) {
        $body = "Daily digest — clean/no-alert scans:\n\n" . implode("\n", array_map(
            static fn (array $e) => sprintf('%s: %d findings at %s', $e['site_id'], $e['total_findings'], $e['scanned_at']),
            $entries,
        ));
        foreach ($mailConfig['to'] as $recipient) {
            mail($recipient, 'Security scanner daily digest', $body);
        }
    }
}

$logger->info('run complete', ['sites_scanned' => count($manifest)]);
