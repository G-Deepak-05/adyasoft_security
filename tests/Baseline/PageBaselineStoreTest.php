<?php
// tests/Baseline/PageBaselineStoreTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Baseline;

use AdyaSoft\Security\Baseline\PageBaselineStore;
use PHPUnit\Framework\TestCase;

final class PageBaselineStoreTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/page-baseline-' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testLoadReturnsEmptyArrayWhenNoBaselineYet(): void
    {
        $store = new PageBaselineStore($this->path);
        $this->assertSame([], $store->load());
    }

    public function testSaveThenLoadRoundTrips(): void
    {
        $store = new PageBaselineStore($this->path);
        $pages = [['id' => 10, 'title' => 'About', 'slug' => 'about', 'author_login' => 'boss', 'published_at' => '2024-01-01', 'modified_at' => '2024-01-01', 'content_hash' => 'abc']];

        $store->save($pages);

        $this->assertSame($pages, $store->load());
    }
}
