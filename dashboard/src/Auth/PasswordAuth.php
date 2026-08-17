<?php
// dashboard/src/Auth/PasswordAuth.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Auth;

final class PasswordAuth
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function verify(string $username, string $password): ?int
    {
        $stmt = $this->pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if ($row === false || !password_verify($password, $row['password_hash'])) {
            return null;
        }

        return (int) $row['id'];
    }
}
