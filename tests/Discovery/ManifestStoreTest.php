<?php
// tests/Discovery/ManifestStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Discovery;

use AdyaSoft\Security\Discovery\ManifestStore;
use PHPUnit\Framework\TestCase;

final class ManifestStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/manifest-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenFileMissing(): void
    {
        $store = new ManifestStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new ManifestStore($this->path);
        $manifest = ['abc123' => ['site_id' => 'abc123', 'path' => '/x', 'status' => 'active']];

        $store->save($manifest);

        $this->assertSame($manifest, $store->load());
    }

    public function testReconcileAddsNewSiteWithFirstSeenAndLastSeen(): void
    {
        $store = new ManifestStore($this->path);
        $updated = $store->reconcile([], ['/home/user/public_html']);

        $siteId = array_key_first($updated);
        $entry = $updated[$siteId];

        $this->assertSame('/home/user/public_html', $entry['path']);
        $this->assertSame('active', $entry['status']);
        $this->assertArrayHasKey('first_seen', $entry);
        $this->assertArrayHasKey('last_seen', $entry);
    }

    public function testReconcileMarksMissingSiteRatherThanDeletingIt(): void
    {
        $store = new ManifestStore($this->path);
        $first = $store->reconcile([], ['/home/user/public_html']);

        $second = $store->reconcile($first, []); // site no longer discovered

        $siteId = array_key_first($second);
        $this->assertArrayHasKey($siteId, $second);
        $this->assertSame('missing', $second[$siteId]['status']);
    }

    public function testReconcileReactivatesAPreviouslyMissingSite(): void
    {
        $store = new ManifestStore($this->path);
        $first = $store->reconcile([], ['/home/user/public_html']);
        $second = $store->reconcile($first, []);

        $third = $store->reconcile($second, ['/home/user/public_html']);

        $siteId = array_key_first($third);
        $this->assertSame('active', $third[$siteId]['status']);
        $this->assertSame($first[$siteId]['first_seen'], $third[$siteId]['first_seen']);
    }
}
