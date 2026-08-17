<?php
// dashboard/tests/Auth/CsrfTest.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Tests\Auth;

use AdyaSoft\Dashboard\Auth\Csrf;
use PHPUnit\Framework\TestCase;

final class CsrfTest extends TestCase
{
    public function testMatchingTokensAreAccepted(): void
    {
        $token = bin2hex(random_bytes(32));

        $this->assertTrue(Csrf::matches($token, $token));
    }

    public function testDifferentTokensAreRejected(): void
    {
        $this->assertFalse(Csrf::matches(bin2hex(random_bytes(32)), bin2hex(random_bytes(32))));
    }

    public function testMissingSubmittedTokenIsRejected(): void
    {
        $token = bin2hex(random_bytes(32));

        $this->assertFalse(Csrf::matches($token, null));
        $this->assertFalse(Csrf::matches($token, ''));
        $this->assertFalse(Csrf::matches($token, ['array']));
    }

    public function testMissingSessionTokenIsRejectedEvenIfSubmittedTokenIsEmpty(): void
    {
        $this->assertFalse(Csrf::matches(null, null));
        $this->assertFalse(Csrf::matches(null, 'anything'));
        $this->assertFalse(Csrf::matches('', ''));
    }

    public function testTokenIsGeneratedOnceAndReusedForTheSession(): void
    {
        $_SESSION = [];

        $first = Csrf::token();
        $second = Csrf::token();

        $this->assertSame(64, strlen($first));
        $this->assertSame($first, $second);
        $this->assertSame($first, $_SESSION[Csrf::FIELD]);

        $_SESSION = [];
    }

    public function testFieldRendersTheHiddenInputWithTheSessionToken(): void
    {
        $_SESSION = [];

        $html = Csrf::field();

        $this->assertStringContainsString('name="csrf_token"', $html);
        $this->assertStringContainsString('value="' . $_SESSION[Csrf::FIELD] . '"', $html);

        $_SESSION = [];
    }
}
