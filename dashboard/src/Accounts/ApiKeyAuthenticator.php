<?php
// dashboard/src/Accounts/ApiKeyAuthenticator.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class ApiKeyAuthenticator
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function authenticate(?string $authorizationHeader): ?int
    {
        if ($authorizationHeader === null) {
            return null;
        }

        if (preg_match('/^Bearer\s+(.+)$/i', trim($authorizationHeader), $matches) !== 1) {
            return null;
        }

        $providedHash = hash('sha256', $matches[1]);

        $stmt = $this->pdo->query('SELECT id, api_key_hash FROM accounts WHERE revoked_at IS NULL');
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            if (hash_equals($row['api_key_hash'], $providedHash)) {
                return (int) $row['id'];
            }
        }

        return null;
    }
}
