<?php
// tests/WordPress/PageRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\Tests\Fixtures\SqliteWpSchema;
use AdyaSoft\Security\WordPress\PageRepository;
use PHPUnit\Framework\TestCase;

final class PageRepositoryTest extends TestCase
{
    public function testReturnsPublishedPagesWithAuthorLoginAndContentHash(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);
        SqliteWpSchema::insertPage($pdo, 'wp_', 10, 1, 'About', 'about', 'Hello world', '2024-01-05 00:00:00', '2024-01-05 00:00:00');

        $repo = new PageRepository($pdo, 'wp_');
        $pages = $repo->findPublishedPages();

        $this->assertCount(1, $pages);
        $this->assertSame('About', $pages[0]['title']);
        $this->assertSame('about', $pages[0]['slug']);
        $this->assertSame('boss', $pages[0]['author_login']);
        $this->assertSame(hash('sha256', 'Hello world'), $pages[0]['content_hash']);
    }

    public function testExcludesDraftAndNonPagePostTypes(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        SqliteWpSchema::insertUser($pdo, 'wp_', 1, 'boss', 'boss@example.com', '2024-01-01 00:00:00', ['administrator']);
        SqliteWpSchema::insertPage($pdo, 'wp_', 10, 1, 'Draft Page', 'draft', 'x', '2024-01-05 00:00:00', '2024-01-05 00:00:00');
        $pdo->exec("UPDATE wp_posts SET post_status = 'draft' WHERE ID = 10");
        $pdo->exec("INSERT INTO wp_posts (ID, post_author, post_title, post_name, post_content, post_status, post_type, post_date, post_modified)
                     VALUES (11, 1, 'A Post', 'a-post', 'y', 'publish', 'post', '2024-01-06 00:00:00', '2024-01-06 00:00:00')");

        $repo = new PageRepository($pdo, 'wp_');
        $pages = $repo->findPublishedPages();

        $this->assertSame([], $pages);
    }
}
