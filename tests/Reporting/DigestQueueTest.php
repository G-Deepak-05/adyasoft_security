<?php
// tests/Reporting/DigestQueueTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Reporting;

use AdyaSoft\Security\Reporting\DigestQueue;
use PHPUnit\Framework\TestCase;

final class DigestQueueTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/digest-' . uniqid('', true) . '.jsonl';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testAppendThenFlushReturnsAllQueuedEntries(): void
    {
        $queue = new DigestQueue($this->path);

        $queue->append(['site_id' => 'a', 'summary' => 'clean scan']);
        $queue->append(['site_id' => 'b', 'summary' => 'clean scan']);

        $entries = $queue->flush();

        $this->assertCount(2, $entries);
        $this->assertSame('a', $entries[0]['site_id']);
    }

    public function testFlushEmptiesTheQueue(): void
    {
        $queue = new DigestQueue($this->path);
        $queue->append(['site_id' => 'a', 'summary' => 'clean scan']);

        $queue->flush();
        $second = $queue->flush();

        $this->assertSame([], $second);
    }

    public function testFlushOnEmptyQueueReturnsEmptyArray(): void
    {
        $queue = new DigestQueue($this->path);

        $this->assertSame([], $queue->flush());
    }
}
