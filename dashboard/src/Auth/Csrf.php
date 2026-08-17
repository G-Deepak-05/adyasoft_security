<?php
// dashboard/src/Auth/Csrf.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

/**
 * Per-session CSRF token for the dashboard's state-mutating POST forms.
 *
 * The most serious concrete risk this closes: a forged POST to accounts.php
 * carrying a revoke_id silently revokes a hosting account's API key, after
 * which every scanner on that account 401s forever with no visible signal.
 */
final class Csrf
{
    public const FIELD = 'csrf_token';

    /**
     * Return the session's CSRF token, generating one on first use.
     * Requires an already-started session.
     */
    public static function token(): string
    {
        $existing = $_SESSION[self::FIELD] ?? null;

        if (!is_string($existing) || $existing === '') {
            $_SESSION[self::FIELD] = bin2hex(random_bytes(32));
        }

        return (string) $_SESSION[self::FIELD];
    }

    /**
     * Constant-time comparison of an expected and a submitted token.
     * Pure — takes both values as arguments so it is testable without
     * superglobals.
     */
    public static function matches(mixed $expected, mixed $submitted): bool
    {
        if (!is_string($expected) || $expected === '') {
            return false;
        }

        if (!is_string($submitted) || $submitted === '') {
            return false;
        }

        return hash_equals($expected, $submitted);
    }

    /**
     * Verify the current request's submitted token against the session's.
     */
    public static function check(): bool
    {
        return self::matches($_SESSION[self::FIELD] ?? null, $_POST[self::FIELD] ?? null);
    }

    /**
     * The hidden form field to embed in every state-mutating POST form.
     */
    public static function field(): string
    {
        return '<input type="hidden" name="' . self::FIELD . '" value="'
            . htmlspecialchars(self::token(), ENT_QUOTES) . '">';
    }
}
