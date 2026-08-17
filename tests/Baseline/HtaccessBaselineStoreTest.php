<?php
// tests/Baseline/HtaccessBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\HtaccessBaselineStore;
use PHPUnit\Framework\TestCase;

final class HtaccessBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/htaccess-baseline-' . uniqid('', true) . '.txt';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsNullWhenNoBaselineYet(): void
    {
        $store = new HtaccessBaselineStore($this->path);
        $this->assertNull($store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new HtaccessBaselineStore($this->path);
        $store->save("RewriteEngine On\n");

        $this->assertSame("RewriteEngine On\n", $store->load());
    }
}
