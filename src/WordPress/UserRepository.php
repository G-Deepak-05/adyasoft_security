<?php
// src/WordPress/UserRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class UserRepository
{
    private const RELEVANT_ROLES = ['administrator', 'editor'];

    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function findAdminAndEditorUsers(): array
    {
        $stmt = $this->pdo->query(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value
             FROM {$this->tablePrefix}users u
             JOIN {$this->tablePrefix}usermeta m
               ON m.user_id = u.ID AND m.meta_key = '{$this->tablePrefix}capabilities'"
        );

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $roles = $this->rolesFromSerializedCapabilities($row['meta_value']);
            $relevant = array_values(array_intersect($roles, self::RELEVANT_ROLES));
            if ($relevant === []) {
                continue;
            }
            $results[] = [
                'id' => (int) $row['ID'],
                'user_login' => $row['user_login'],
                'user_email' => $row['user_email'],
                'user_registered' => $row['user_registered'],
                'roles' => $relevant,
            ];
        }

        return $results;
    }

    private function rolesFromSerializedCapabilities(string $serialized): array
    {
        $unserialized = @unserialize($serialized, ['allowed_classes' => false]);
        if (!is_array($unserialized)) {
            return [];
        }
        return array_keys(array_filter($unserialized));
    }
}
