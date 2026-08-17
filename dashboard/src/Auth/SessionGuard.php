<?php
// dashboard/src/Auth/SessionGuard.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

final class SessionGuard
{
    public static function login(int $userId): void
    {
        // Rotate the session id on successful authentication to prevent
        // session fixation. Guarded so unit tests without an active session
        // (and CLI usage) don't emit a warning.
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        $_SESSION['user_id'] = $userId;
    }

    public static function check(): bool
    {
        return isset($_SESSION['user_id']);
    }

    public static function currentUserId(): ?int
    {
        return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    }

    public static function logout(): void
    {
        unset($_SESSION['user_id'], $_SESSION[Csrf::FIELD]);
    }
}
