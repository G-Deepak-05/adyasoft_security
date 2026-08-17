<?php
// tests/Support/ConfigLoaderTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Support;

use AdyaSoft\Security\Support\ConfigLoader;
use PHPUnit\Framework\TestCase;

final class ConfigLoaderTest extends TestCase
{
    public function testLoadReturnsArrayFromConfigFile(): void
    {
        $path = sys_get_temp_dir() . '/scanner-config-' . uniqid('', true) . '.php';
        file_put_contents($path, "<?php\nreturn ['weight' => 5];\n");

        $config = ConfigLoader::load($path);

        $this->assertSame(['weight' => 5], $config);
        unlink($path);
    }

    public function testLoadThrowsWhenFileMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        ConfigLoader::load('/nonexistent/path/config.php');
    }
}
