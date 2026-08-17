<?php
// src/Scanner.php
declare(strict_types=1);

namespace AdyaSoft\Security;

use AdyaSoft\Security\Baseline\FileBaselineStore;
use AdyaSoft\Security\Baseline\FileScanner;
use AdyaSoft\Security\Baseline\HtaccessBaselineStore;
use AdyaSoft\Security\Baseline\PageBaselineStore;
use AdyaSoft\Security\Baseline\UserBaselineStore;
use AdyaSoft\Security\Detectors\CoreIntegrityDetector;
use AdyaSoft\Security\Detectors\EntropyAnalyzer;
use AdyaSoft\Security\Detectors\FileDetector;
use AdyaSoft\Security\Detectors\HtaccessDetector;
use AdyaSoft\Security\Detectors\MuPluginsDetector;
use AdyaSoft\Security\Detectors\PageDetector;
use AdyaSoft\Security\Detectors\PluginIntegrityDetector;
use AdyaSoft\Security\Detectors\UploadsPhpDetector;
use AdyaSoft\Security\Detectors\UserDetector;
use AdyaSoft\Security\Reporting\ReportBuilder;
use AdyaSoft\Security\Scoring\RiskScorer;
use AdyaSoft\Security\Support\Logger;
use AdyaSoft\Security\WordPress\ChecksumClient;
use AdyaSoft\Security\WordPress\DbConnectionFactory;
use AdyaSoft\Security\WordPress\OptionsRepository;
use AdyaSoft\Security\WordPress\PageRepository;
use AdyaSoft\Security\WordPress\UserRepository;
use AdyaSoft\Security\WordPress\WpConfigParser;

final class Scanner
{
    public function __construct(
        private readonly string $dataDir,
        private readonly array $scoringConfig,
        private readonly array $sitesConfig,
    ) {
    }

    public function scanSite(string $sitePath, string $siteId, string $tier): array
    {
        // Defensive: $siteId is interpolated into filesystem paths below. Every caller
        // sources it from ManifestStore::reconcile(), which always produces a 12-char
        // hex SHA1 slice — anything else indicates a programming error in the caller.
        if (preg_match('/^[a-f0-9]{12}$/', $siteId) !== 1) {
            throw new \InvalidArgumentException("Invalid site_id format: {$siteId}");
        }

        $siteDataDir = "{$this->dataDir}/sites/{$siteId}";
        if (!is_dir("{$siteDataDir}/scans")) {
            mkdir("{$siteDataDir}/scans", 0700, true);
        }
        $logger = new Logger("{$siteDataDir}/scans/{$this->scanId($siteId, $tier)}.log");
        $siteOverrides = $this->sitesConfig[$siteId] ?? [];
        $knownGoodUsers = $siteOverrides['known_good_users'] ?? [];
        $knownContributors = $siteOverrides['known_contributor_logins'] ?? $knownGoodUsers;
        $siteDomains = $siteOverrides['domains'] ?? [];

        $findings = [];
        $degraded = [];

        // --- users, pages, active plugins: require a parseable wp-config.php ---
        $credentials = null;
        if (is_file("{$sitePath}/wp-config.php")) {
            $credentials = WpConfigParser::parse(file_get_contents("{$sitePath}/wp-config.php"));
        }

        $activePlugins = [];
        if ($credentials === null) {
            $logger->warning('wp-config.php not parseable; skipping DB-backed checks', ['site_id' => $siteId]);
            $degraded[] = 'DB-backed checks skipped: wp-config.php not parseable';
        } else {
            try {
                $pdo = DbConnectionFactory::createMysql($credentials);

                $userRepo = new UserRepository($pdo, $credentials['table_prefix']);
                $userBaselineStore = new UserBaselineStore("{$siteDataDir}/baseline/users.json");
                $previousUsers = $userBaselineStore->load();
                $currentUsers = $userRepo->findAdminAndEditorUsers();
                $findings = array_merge($findings, (new UserDetector($knownGoodUsers))->detect($currentUsers, $previousUsers));
                $userBaselineStore->save($currentUsers);

                $pageRepo = new PageRepository($pdo, $credentials['table_prefix']);
                $pageBaselineStore = new PageBaselineStore("{$siteDataDir}/baseline/pages.json");
                $previousPages = $pageBaselineStore->load();
                $currentPages = $pageRepo->findPublishedPages();
                $findings = array_merge($findings, (new PageDetector($knownContributors))->detect($currentPages, $previousPages));
                $pageBaselineStore->save($currentPages);

                if ($tier === 'expensive') {
                    $activePlugins = (new OptionsRepository($pdo, $credentials['table_prefix']))->getActivePlugins();
                }
            } catch (\PDOException $e) {
                $logger->error('DB connection failed; skipping DB-backed checks', ['error' => $e->getMessage()]);
                $degraded[] = 'DB-backed checks skipped: connection failed';
            }
        }

        // --- .htaccess: filesystem only, always runs ---
        $htaccessBaselineStore = new HtaccessBaselineStore("{$siteDataDir}/baseline/htaccess.json.txt");
        $previousHtaccess = $htaccessBaselineStore->load();
        $currentHtaccess = is_file("{$sitePath}/.htaccess") ? file_get_contents("{$sitePath}/.htaccess") : null;
        $findings = array_merge($findings, (new HtaccessDetector($siteDomains))->detect($currentHtaccess, $previousHtaccess));
        if ($currentHtaccess !== null) {
            $htaccessBaselineStore->save($currentHtaccess);
        }

        // --- expensive tier: files, core/plugin integrity, entropy ---
        if ($tier === 'expensive') {
            $fileBaselineStore = new FileBaselineStore("{$siteDataDir}/baseline/files.json");
            $previousFiles = $fileBaselineStore->load();
            $currentFiles = (new FileScanner($sitePath))->scan();

            $findings = array_merge($findings, (new FileDetector())->detect($currentFiles, $previousFiles));
            $findings = array_merge($findings, (new UploadsPhpDetector())->detect($currentFiles));
            $findings = array_merge($findings, (new MuPluginsDetector())->detect($currentFiles, $previousFiles));

            $checksumClient = new ChecksumClient(static function (string $url): ?array {
                $json = @file_get_contents($url);
                if ($json === false) {
                    return null;
                }
                $decoded = json_decode($json, true);
                return is_array($decoded) ? $decoded : null;
            });

            if (is_file("{$sitePath}/wp-includes/version.php")) {
                $wpVersion = $this->readWpVersion("{$sitePath}/wp-includes/version.php");
                $coreChecksums = $wpVersion !== null ? $checksumClient->getCoreChecksums($wpVersion) : null;
                if ($coreChecksums !== null && $coreChecksums !== []) {
                    $findings = array_merge($findings, (new CoreIntegrityDetector())->detect($currentFiles, $coreChecksums));
                } else {
                    $logger->warning('core checksums unavailable; skipping core integrity check', ['version' => $wpVersion]);
                    $degraded[] = 'core integrity check skipped: checksums unavailable for version ' . ($wpVersion ?? 'unknown');
                }
            }

            foreach ($activePlugins as $pluginFile) {
                // Defensive: $pluginFile comes from the site's own active_plugins option,
                // which is attacker-controllable on an already-compromised site and is
                // interpolated into a filesystem path below. Only accept the canonical
                // "slug/file.php" shape (no traversal, no separators beyond one slash).
                if (!is_string($pluginFile) || preg_match('/^[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+\.php$/', $pluginFile) !== 1) {
                    $logger->warning('active_plugins entry has unsafe format; skipping checksum check', [
                        'plugin' => is_string($pluginFile) ? $pluginFile : gettype($pluginFile),
                    ]);
                    $degraded[] = 'plugin integrity check skipped: active_plugins entry has unsafe format';
                    continue;
                }
                $slug = dirname($pluginFile);
                if ($slug === '.') {
                    continue;
                }
                $pluginVersion = $this->readPluginVersion("{$sitePath}/wp-content/plugins/{$pluginFile}");
                if ($pluginVersion === null) {
                    $logger->warning('plugin version header not found; skipping checksum check', ['plugin' => $slug]);
                    $degraded[] = "plugin integrity check skipped for {$slug}: version header not found";
                    continue;
                }
                $pluginChecksums = $checksumClient->getPluginChecksums($slug, $pluginVersion);
                if ($pluginChecksums !== null && $pluginChecksums !== []) {
                    $findings = array_merge($findings, (new PluginIntegrityDetector())->detect($currentFiles, $slug, $pluginChecksums));
                } else {
                    $logger->warning('plugin checksums unavailable; skipping check', ['plugin' => $slug, 'version' => $pluginVersion]);
                    $degraded[] = "plugin integrity check skipped for {$slug}: checksums unavailable";
                }
            }

            $entropyAnalyzer = new EntropyAnalyzer();
            foreach (array_keys($currentFiles) as $relativePath) {
                if (strtolower(pathinfo($relativePath, PATHINFO_EXTENSION)) !== 'php') {
                    continue;
                }
                foreach ($entropyAnalyzer->analyzeFile("{$sitePath}/{$relativePath}") as $entropyFinding) {
                    $entropyFinding['path'] = $relativePath;
                    $findings[] = $entropyFinding;
                }
            }

            $fileBaselineStore->save($currentFiles);
        }

        $scorer = new RiskScorer($this->scoringConfig['weights'], $this->scoringConfig['severity_thresholds']);
        $scored = $scorer->score($findings);

        $report = (new ReportBuilder())->build([
            'site_id' => $siteId,
            'site_path' => $sitePath,
            'scan_id' => $this->scanId($siteId, $tier),
            'mode' => 'audit',
            'scanned_at' => date('c'),
            'tier' => $tier,
            'degraded_checks' => $degraded,
        ], $scored);

        $reportPath = "{$siteDataDir}/scans/{$report['meta']['scan_id']}.json";
        $written = file_put_contents($reportPath, (new ReportBuilder())->toJson($report));
        if ($written === false) {
            $logger->error('failed to write scan report to disk', ['path' => $reportPath]);
        }

        $logger->info('scan complete', ['total_findings' => $report['summary']['total_findings']]);

        return $report;
    }

    private function readWpVersion(string $versionFilePath): ?string
    {
        $wp_version = null;
        (function () use ($versionFilePath, &$wp_version): void {
            include $versionFilePath;
        })();
        return $wp_version;
    }

    private function readPluginVersion(string $pluginMainFilePath): ?string
    {
        if (!is_file($pluginMainFilePath)) {
            return null;
        }

        $header = file_get_contents($pluginMainFilePath, false, null, 0, 8192);
        if ($header === false) {
            return null;
        }

        if (preg_match('/^\s*(?:\*|\/\*+)?\s*Version:\s*(.+)$/mi', $header, $matches) === 1) {
            return trim($matches[1]);
        }

        return null;
    }

    private function scanId(string $siteId, string $tier): string
    {
        static $ids = [];
        return $ids["{$siteId}:{$tier}"] ??= $siteId . '-' . $tier . '-' . date('Ymd-His');
    }
}
