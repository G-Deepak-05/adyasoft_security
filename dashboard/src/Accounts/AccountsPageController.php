<?php
// dashboard/src/Accounts/AccountsPageController.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Accounts;

final class AccountsPageController
{
    public function __construct(private readonly AccountRepository $repository)
    {
    }

    public function handleCreate(string $name): array
    {
        return $this->repository->create($name);
    }

    public function handleRevoke(int $id): void
    {
        $this->repository->revoke($id);
    }

    public function buildViewModel(): array
    {
        return ['accounts' => $this->repository->all()];
    }
}
