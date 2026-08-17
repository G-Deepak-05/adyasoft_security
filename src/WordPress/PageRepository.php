<?php
// src/WordPress/PageRepository.php
declare(strict_types=1);

namespace AdyaSoft\Security\WordPress;

final class PageRepository
{
    public function __construct(private readonly \PDO $pdo, private readonly string $tablePrefix)
    {
    }

    public function findPublishedPages(): array
    {
        $stmt = $this->pdo->query(
            "SELECT p.ID, p.post_title, p.post_name, p.post_content, p.post_date, p.post_modified, u.user_login
             FROM {$this->tablePrefix}posts p
             JOIN {$this->tablePrefix}users u ON u.ID = p.post_author
             WHERE p.post_type = 'page' AND p.post_status = 'publish'"
        );

        $results = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $results[] = [
                'id' => (int) $row['ID'],
                'title' => $row['post_title'],
                'slug' => $row['post_name'],
                'author_login' => $row['user_login'],
                'published_at' => $row['post_date'],
                'modified_at' => $row['post_modified'],
                'content_hash' => hash('sha256', $row['post_content']),
            ];
        }

        return $results;
    }
}
