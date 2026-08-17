<?php
// tests/Support/LoggerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Support;

use AdyaSoft\Security\Support\Logger;
use PHPUnit\Framework\TestCase;

final class LoggerTest extends TestCase
{
    private string $logFile;

    protected function setUp(): void
    {
        $this->logFile = sys_get_temp_dir() . '/scanner-log-' . uniqid('', true) . '.jsonl';
    }

    protected function tearDown(): void
    {
        if (is_file($this->logFile)) {
            unlink($this->logFile);
        }
    }

    public function testInfoAppendsOneJsonLineWithLevelMessageAndContext(): void
    {
        $logger = new Logger($this->logFile);

        $logger->info('scan started', ['site_id' => 'site-a']);

        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES);
        $this->assertCount(1, $lines);

        $decoded = json_decode($lines[0], true);
        $this->assertSame('info', $decoded['level']);
        $this->assertSame('scan started', $decoded['message']);
        $this->assertSame('site-a', $decoded['context']['site_id']);
        $this->assertArrayHasKey('ts', $decoded);
    }

    public function testMultipleCallsAppendRatherThanOverwrite(): void
    {
        $logger = new Logger($this->logFile);

        $logger->info('first');
        $logger->warning('second');
        $logger->error('third');

        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES);
        $this->assertCount(3, $lines);
        $this->assertSame('warning', json_decode($lines[1], true)['level']);
        $this->assertSame('error', json_decode($lines[2], true)['level']);
    }
}
