<?php
// tests/WordPress/WpConfigParserTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\WordPress\WpConfigParser;
use PHPUnit\Framework\TestCase;

final class WpConfigParserTest extends TestCase
{
    public function testParsesStandardSingleQuotedWpConfig(): void
    {
        $contents = <<<'PHP'
        <?php
        define( 'DB_NAME', 'wp_mydb' );
        define( 'DB_USER', 'wp_user' );
        define( 'DB_PASSWORD', 'S3cr3t!' );
        define( 'DB_HOST', 'localhost' );
        $table_prefix = 'wp_';
        require_once ABSPATH . 'wp-settings.php';
        PHP;

        $result = WpConfigParser::parse($contents);

        $this->assertSame([
            'db_name' => 'wp_mydb',
            'db_user' => 'wp_user',
            'db_password' => 'S3cr3t!',
            'db_host' => 'localhost',
            'table_prefix' => 'wp_',
        ], $result);
    }

    public function testParsesDoubleQuotedAndCompactSpacing(): void
    {
        $contents = <<<'PHP'
        <?php
        define("DB_NAME","otherdb");
        define("DB_USER","otheruser");
        define("DB_PASSWORD","p@ss");
        define("DB_HOST","127.0.0.1");
        $table_prefix="wp7x_";
        PHP;

        $result = WpConfigParser::parse($contents);

        $this->assertSame('otherdb', $result['db_name']);
        $this->assertSame('wp7x_', $result['table_prefix']);
    }

    public function testReturnsNullWhenDbNameMissing(): void
    {
        $contents = "<?php\ndefine('DB_USER', 'u');\n";
        $this->assertNull(WpConfigParser::parse($contents));
    }

    public function testReturnsNullWhenCredentialsComeFromGetenv(): void
    {
        $contents = "<?php\ndefine('DB_NAME', getenv('DB_NAME'));\n";
        $this->assertNull(WpConfigParser::parse($contents));
    }
}
