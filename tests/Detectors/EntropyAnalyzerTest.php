<?php
// tests/Detectors/EntropyAnalyzerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\EntropyAnalyzer;
use PHPUnit\Framework\TestCase;

final class EntropyAnalyzerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/entropy-' . uniqid('', true) . '.php';
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testFlagsHighEntropyStringLiteral(): void
    {
        // A long, high-entropy (effectively random-looking) base64 blob.
        $blob = 'ZGVhZGJlZWZjb2ZmZWViYWJlMTIzNDU2Nzg5MHFiY2RlZm9wcXJzdHV2d3l6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
        file_put_contents($this->path, "<?php\n\$x = '{$blob}';\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_high', $types);
    }

    public function testDoesNotFlagOrdinaryShortStrings(): void
    {
        file_put_contents($this->path, "<?php\necho 'hello world';\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $this->assertSame([], $findings);
    }

    public function testFlagsEvalBase64DecodeChain(): void
    {
        file_put_contents($this->path, "<?php\neval(base64_decode(\$_POST['x']));\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_obfuscation_pattern', $types);
    }

    public function testFlagsCallUserFuncFedFromRequestSuperglobal(): void
    {
        file_put_contents($this->path, "<?php\ncall_user_func(\$_GET['fn'], 'arg');\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_obfuscation_pattern', $types);
    }

    public function testDoesNotFlagOrdinaryFunctionCalls(): void
    {
        file_put_contents($this->path, "<?php\nfunction add(\$a, \$b) { return \$a + \$b; }\necho add(1, 2);\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $this->assertSame([], $findings);
    }
}
