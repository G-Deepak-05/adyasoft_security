<?php
// src/Detectors/HtaccessDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class HtaccessDetector
{
    public function __construct(private readonly array $siteDomains)
    {
    }

    public function detect(?string $currentContents, ?string $baselineContents): array
    {
        $findings = [];

        if ($currentContents !== $baselineContents) {
            $findings[] = [
                'type' => 'htaccess_diff',
                'details' => ['baseline' => $baselineContents, 'current' => $currentContents],
            ];
        }

        if ($currentContents !== null) {
            foreach ($this->findExternalRedirectTargets($currentContents) as $target) {
                $findings[] = [
                    'type' => 'htaccess_external_redirect',
                    'details' => ['target' => $target],
                ];
            }
        }

        return $findings;
    }

    private function findExternalRedirectTargets(string $contents): array
    {
        $targets = [];
        $lines = preg_split('/\r\n|\r|\n/', $contents);

        foreach ($lines as $line) {
            if (preg_match('/^\s*(?:RewriteRule|RedirectMatch|Redirect)\s+.*?(https?:\/\/\S+)/i', $line, $matches) === 1) {
                $target = $matches[1];
                $host = parse_url($target, PHP_URL_HOST);
                if ($host !== null && !in_array($host, $this->siteDomains, true)) {
                    $targets[] = $target;
                }
            }
        }

        return $targets;
    }
}
