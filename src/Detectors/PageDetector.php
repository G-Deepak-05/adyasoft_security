<?php
// src/Detectors/PageDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class PageDetector
{
    public function __construct(private readonly array $knownContributorLogins)
    {
    }

    public function detect(array $currentPages, array $baselinePages): array
    {
        $baselineById = [];
        foreach ($baselinePages as $page) {
            $baselineById[$page['id']] = $page;
        }

        $findings = [];

        foreach ($currentPages as $page) {
            $baseline = $baselineById[$page['id']] ?? null;

            if ($baseline === null) {
                $findings[] = ['type' => 'page_new', 'page_id' => $page['id'], 'details' => $page];
            } elseif ($baseline['content_hash'] !== $page['content_hash']) {
                $findings[] = ['type' => 'page_modified', 'page_id' => $page['id'], 'details' => $page];
            }

            if (!in_array($page['author_login'], $this->knownContributorLogins, true)) {
                $findings[] = ['type' => 'page_unexpected_author', 'page_id' => $page['id'], 'details' => $page];
            }
        }

        return $findings;
    }
}
