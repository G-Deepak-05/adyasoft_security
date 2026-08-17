<?php
// dashboard/src/Auth/SessionGuard.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

final class SessionGuard
{
    public static function login(int $userId): void
    {
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
        unset($_SESSION['user_id']);
    }
}
