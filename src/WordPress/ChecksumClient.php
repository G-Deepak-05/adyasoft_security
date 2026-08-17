<?php
// src/WordPress/ChecksumClient.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class ChecksumClient
{
    /** @param callable(string): ?array $httpGetJson */
    public function __construct(private readonly mixed $httpGetJson)
    {
    }

    public function getCoreChecksums(string $version, string $locale = 'en_US'): ?array
    {
        $url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            urlencode($version),
            urlencode($locale),
        );

        $response = ($this->httpGetJson)($url);

        if (!is_array($response) || !isset($response['checksums']) || !is_array($response['checksums'])) {
            return null;
        }

        return $response['checksums'];
    }

    public function getPluginChecksums(string $slug, string $version): ?array
    {
        $url = sprintf(
            'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
            urlencode($slug),
            urlencode($version),
        );

        $response = ($this->httpGetJson)($url);

        if (!is_array($response) || !isset($response['files']) || !is_array($response['files'])) {
            return null;
        }

        $checksums = [];
        foreach ($response['files'] as $relativePath => $meta) {
            if (is_array($meta) && isset($meta['sha256'])) {
                $checksums[$relativePath] = $meta['sha256'];
            }
        }

        return $checksums;
    }
}
