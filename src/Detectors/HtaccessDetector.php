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
                'path' => '.htaccess',
                'details' => ['baseline' => $baselineContents, 'current' => $currentContents],
            ];
        }

        if ($currentContents !== null) {
            foreach ($this->findExternalRedirectTargets($currentContents) as $target) {
                $findings[] = [
                    'type' => 'htaccess_external_redirect',
                    'path' => '.htaccess',
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
        // Hostnames are case-insensitive; normalize both sides so a differently-cased
        // form of the site's own domain isn't misreported as an external redirect.
        $knownDomains = array_map(
            static fn ($domain) => strtolower((string) $domain),
            $this->siteDomains,
        );

        foreach ($lines as $line) {
            if (preg_match('/^\s*(?:RewriteRule|RedirectMatch|Redirect)\s+.*?(https?:\/\/\S+)/i', $line, $matches) === 1) {
                $target = $matches[1];
                $host = parse_url($target, PHP_URL_HOST);
                if ($host !== null && !in_array(strtolower($host), $knownDomains, true)) {
                    $targets[] = $target;
                }
            }
        }

        return $targets;
    }
}
