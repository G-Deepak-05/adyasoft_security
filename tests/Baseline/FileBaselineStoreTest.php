<?php
// tests/Baseline/FileBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\FileBaselineStore;
use PHPUnit\Framework\TestCase;

final class FileBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/file-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new FileBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new FileBaselineStore($this->path);
        $entries = ['wp-content/index.php' => ['sha256' => 'abc', 'size' => 10, 'mtime' => 123, 'permissions' => '0644']];

        $store->save($entries);

        $this->assertSame($entries, $store->load());
    }
}
