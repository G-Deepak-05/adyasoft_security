<?php
// tests/WordPress/OptionsRepositoryTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\WordPress;

use AdyaSoft\Security\Tests\Fixtures\SqliteWpSchema;
use AdyaSoft\Security\WordPress\OptionsRepository;
use PHPUnit\Framework\TestCase;

final class OptionsRepositoryTest extends TestCase
{
    public function testGetActivePluginsUnserializesTheOption(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();
        $plugins = ['akismet/akismet.php', 'contact-form-7/wp-contact-form-7.php'];
        SqliteWpSchema::setOption($pdo, 'wp_', 'active_plugins', serialize($plugins));

        $repo = new OptionsRepository($pdo, 'wp_');

        $this->assertSame($plugins, $repo->getActivePlugins());
    }

    public function testGetActivePluginsReturnsEmptyArrayWhenOptionMissing(): void
    {
        $pdo = SqliteWpSchema::createInMemoryDb();

        $repo = new OptionsRepository($pdo, 'wp_');

        $this->assertSame([], $repo->getActivePlugins());
    }
}
