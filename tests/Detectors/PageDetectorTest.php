<?php
// tests/Detectors/PageDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\PageDetector;
use PHPUnit\Framework\TestCase;

final class PageDetectorTest extends TestCase
{
    private function page(int $id, string $login, string $hash): array
    {
        return ['id' => $id, 'title' => "Page {$id}", 'slug' => "page-{$id}", 'author_login' => $login, 'published_at' => '2024-01-01', 'modified_at' => '2024-01-01', 'content_hash' => $hash];
    }

    public function testFlagsNewPage(): void
    {
        $detector = new PageDetector(['boss']);

        $findings = $detector->detect([$this->page(1, 'boss', 'hash1')], []);

        $this->assertSame('page_new', $findings[0]['type']);
        $this->assertSame(1, $findings[0]['page_id']);
    }

    public function testFlagsModifiedPageWhenContentHashDiffers(): void
    {
        $detector = new PageDetector(['boss']);
        $baseline = [$this->page(1, 'boss', 'hash-old')];
        $current = [$this->page(1, 'boss', 'hash-new')];

        $findings = $detector->detect($current, $baseline);

        $this->assertSame('page_modified', $findings[0]['type']);
    }

    public function testFlagsUnexpectedAuthorAdditively(): void
    {
        $detector = new PageDetector(['boss']);

        $findings = $detector->detect([$this->page(1, 'attacker', 'hash1')], []);

        $types = array_column($findings, 'type');
        $this->assertContains('page_new', $types);
        $this->assertContains('page_unexpected_author', $types);
    }

    public function testFlagsModifiedAndUnexpectedAuthorAdditively(): void
    {
        $detector = new PageDetector(['boss']);
        $baseline = [$this->page(1, 'boss', 'hash-old')];
        $current = [$this->page(1, 'attacker', 'hash-new')];

        $findings = $detector->detect($current, $baseline);

        $types = array_column($findings, 'type');
        $this->assertContains('page_modified', $types);
        $this->assertContains('page_unexpected_author', $types);
    }

    public function testNoFindingsForUnchangedKnownPage(): void
    {
        $detector = new PageDetector(['boss']);
        $page = $this->page(1, 'boss', 'hash1');

        $findings = $detector->detect([$page], [$page]);

        $this->assertSame([], $findings);
    }
}
