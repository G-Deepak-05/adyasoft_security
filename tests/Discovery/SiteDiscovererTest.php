<?php
// tests/Discovery/SiteDiscovererTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Discovery;

use AdyaSoft\Security\Discovery\SiteDiscoverer;
use PHPUnit\Framework\TestCase;

final class SiteDiscovererTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/discover-' . uniqid('', true);
        mkdir($this->root, 0700, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    private function makeWpSite(string $path): void
    {
        mkdir($path . '/wp-content', 0700, true);
        mkdir($path . '/wp-admin', 0700, true);
        mkdir($path . '/wp-includes', 0700, true);
        file_put_contents($path . '/wp-config.php', "<?php\n");
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }

    public function testDiscoversSingleSiteInPublicHtml(): void
    {
        $this->makeWpSite($this->root . '/public_html');

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([$this->root . '/public_html'], $found);
    }

    public function testDiscoversMultipleAddonDomainSites(): void
    {
        $this->makeWpSite($this->root . '/public_html');
        $this->makeWpSite($this->root . '/domains/other.com/public_html');

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        sort($found);
        $expected = [
            $this->root . '/domains/other.com/public_html',
            $this->root . '/public_html',
        ];
        sort($expected);
        $this->assertSame($expected, $found);
    }

    public function testExcludesTheScannerOwnDirectory(): void
    {
        $this->makeWpSite($this->root . '/public_html');
        mkdir($this->root . '/security-scanner', 0700, true);

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([$this->root . '/public_html'], $found);
    }

    public function testIgnoresDirectoryMissingWpConfig(): void
    {
        mkdir($this->root . '/public_html/wp-content', 0700, true);
        mkdir($this->root . '/public_html/wp-admin', 0700, true);
        mkdir($this->root . '/public_html/wp-includes', 0700, true);
        // no wp-config.php

        $discoverer = new SiteDiscoverer($this->root);
        $found = $discoverer->discover();

        $this->assertSame([], $found);
    }
}
