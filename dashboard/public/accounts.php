<?php
// dashboard/public/accounts.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\AccountsPageController;
use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;

if (!SessionGuard::check()) {
    header('Location: /login.php');
    exit;
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);
$controller = new AccountsPageController(new AccountRepository($pdo));

$newApiKey = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_name']) && $_POST['create_name'] !== '') {
        $created = $controller->handleCreate((string) $_POST['create_name']);
        $newApiKey = $created['api_key'];
    } elseif (isset($_POST['revoke_id'])) {
        $controller->handleRevoke((int) $_POST['revoke_id']);
    }
}

$viewModel = $controller->buildViewModel();
?>
<!DOCTYPE html>
<html>
<head><title>Manage Accounts</title></head>
<body>
<p><a href="/index.php">Findings</a> | <a href="/logout.php">Log out</a></p>
<?php if ($newApiKey !== null): ?>
    <p><strong>New API key (shown once, copy it now):</strong> <code><?= htmlspecialchars($newApiKey, ENT_QUOTES) ?></code></p>
<?php endif; ?>
<form method="post">
    <label>Account name: <input type="text" name="create_name"></label>
    <button type="submit">Create account</button>
</form>
<table border="1">
<thead><tr><th>Name</th><th>Created</th><th>Status</th><th></th></tr></thead>
<tbody>
<?php foreach ($viewModel['accounts'] as $account): ?>
<tr>
    <td><?= htmlspecialchars($account['name'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($account['created_at'], ENT_QUOTES) ?></td>
    <td><?= $account['revoked'] ? 'Revoked' : 'Active' ?></td>
    <td>
        <?php if (!$account['revoked']): ?>
        <form method="post" style="display:inline;">
            <input type="hidden" name="revoke_id" value="<?= (int) $account['id'] ?>">
            <button type="submit">Revoke</button>
        </form>
        <?php endif; ?>
    </td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</body>
</html>
