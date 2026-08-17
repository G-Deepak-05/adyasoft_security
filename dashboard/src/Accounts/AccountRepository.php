<?php
// dashboard/src/Accounts/AccountRepository.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class AccountRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    public function create(string $name): array
    {
        $apiKey = bin2hex(random_bytes(32));
        $hash = hash('sha256', $apiKey);
        $now = date('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO accounts (name, api_key_hash, revoked_at, created_at) VALUES (?, ?, NULL, ?)'
        );
        $stmt->execute([$name, $hash, $now]);

        return [
            'id' => (int) $this->pdo->lastInsertId(),
            'name' => $name,
            'api_key' => $apiKey,
        ];
    }

    public function all(): array
    {
        $stmt = $this->pdo->query('SELECT id, name, revoked_at, created_at FROM accounts ORDER BY name');

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $results[] = [
                'id' => (int) $row['id'],
                'name' => $row['name'],
                'revoked' => $row['revoked_at'] !== null,
                'created_at' => $row['created_at'],
            ];
        }

        return $results;
    }

    public function revoke(int $id): void
    {
        $stmt = $this->pdo->prepare('UPDATE accounts SET revoked_at = ? WHERE id = ?');
        $stmt->execute([date('Y-m-d H:i:s'), $id]);
    }
}
