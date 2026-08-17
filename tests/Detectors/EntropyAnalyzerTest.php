<?php
// tests/Detectors/EntropyAnalyzerTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\EntropyAnalyzer;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testFlagsAssertWithStringArgument(): void
    {
        file_put_contents($this->path, "<?php\nassert(\"phpinfo()\");\n");

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

    /**
     * Every obfuscation pattern FR-8 requires this detector to catch gets its own
     * snippet here, so a pattern can't silently stop matching without a test failing.
     *
     * @return array<string, array{string}>
     */
    public static function obfuscationSnippetProvider(): array
    {
        return [
            'eval + base64_decode' => ["<?php\neval(base64_decode(\$_POST['x']));\n"],
            'eval + gzinflate' => ["<?php\neval(gzinflate(\$payload));\n"],
            'eval + gzuncompress' => ["<?php\neval(gzuncompress(\$payload));\n"],
            'eval + str_rot13' => ["<?php\neval(str_rot13(\$payload));\n"],
            'assert with string argument' => ["<?php\nassert(\"phpinfo()\");\n"],
            'assert with variable argument' => ["<?php\nassert(\$cmd);\n"],
            'create_function' => ["<?php\n\$f = create_function('\$a', 'return \$a;');\n"],
            'variable variable' => ["<?php\n\$name = 'x';\necho \$\$name;\n"],
            'call_user_func from superglobal' => ["<?php\ncall_user_func(\$_GET['fn'], 'arg');\n"],
            'call_user_func_array from superglobal' => ["<?php\ncall_user_func_array(\$_REQUEST['fn'], []);\n"],
        ];
    }

    #[DataProvider('obfuscationSnippetProvider')]
    public function testFlagsEachObfuscationPattern(string $source): void
    {
        file_put_contents($this->path, $source);

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $types = array_column($findings, 'type');
        $this->assertContains('entropy_obfuscation_pattern', $types);
    }

    public function testDoesNotFlagFunctionWhoseNameMerelyEndsInAssert(): void
    {
        // \b anchor: my_assert(...) is a legitimate helper, not the assert() backdoor.
        file_put_contents($this->path, "<?php\nfunction my_assert(\$s) { return \$s; }\nmy_assert(\"ok\");\n");

        $analyzer = new EntropyAnalyzer();
        $findings = $analyzer->analyzeFile($this->path);

        $this->assertSame([], $findings);
    }
}
