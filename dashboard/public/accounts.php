<?php
// dashboard/public/accounts.php
declare(strict_types=1);

// A production HTTPS deployment should also set 'secure' => true; it is derived
// from $_SERVER['HTTPS'] here so the plain-HTTP `php -S` dev workflow still works.
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']),
]);
session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\AccountRepository;
use AdyaSoft\Dashboard\Accounts\AccountsPageController;
use AdyaSoft\Dashboard\Auth\Csrf;
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

// Without a valid CSRF token the POST body is ignored entirely and the page
// simply re-renders — a forged create/revoke never takes effect.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && Csrf::check()) {
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Accounts</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<div class="container">
    <nav class="navbar">
        <a href="/index.php" class="navbar-brand">🛡️ AdyaSoft Security</a>
        <div class="navbar-links">
            <a href="/index.php">Findings</a>
            <a href="/logout.php">Log out</a>
        </div>
    </nav>

    <?php if ($newApiKey !== null): ?>
        <div class="alert-success">
            <strong>Account Created Successfully!</strong><br>
            New API key (shown once, copy it now):<br><br>
            <code style="font-size: 1.1rem; padding: 0.5rem; display: inline-block; background: rgba(0,0,0,0.4);"><?= htmlspecialchars($newApiKey, ENT_QUOTES) ?></code>
        </div>
    <?php endif; ?>

    <div class="card" style="margin-bottom: 2rem;">
        <h3 style="margin-bottom: 1rem;">Create New Account</h3>
        <form method="post" style="display: flex; gap: 1rem; align-items: flex-end;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(Csrf::token(), ENT_QUOTES) ?>">
            <div class="form-group" style="margin-bottom: 0; flex-grow: 1;">
                <label>Account name</label>
                <input type="text" name="create_name" required>
            </div>
            <button type="submit" class="btn btn-auto">Create account</button>
        </form>
    </div>

    <div class="table-container">
        <table>
        <thead><tr><th>Name</th><th>Created</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach ($viewModel['accounts'] as $account): ?>
        <tr>
            <td style="font-weight: 600;"><?= htmlspecialchars($account['name'], ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($account['created_at'], ENT_QUOTES) ?></td>
            <td>
                <?php if ($account['revoked']): ?>
                    <span class="badge badge-critical">REVOKED</span>
                <?php else: ?>
                    <span class="badge badge-low">ACTIVE</span>
                <?php endif; ?>
            </td>
            <td>
                <?php if (!$account['revoked']): ?>
                <form method="post" style="display:inline;">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(Csrf::token(), ENT_QUOTES) ?>">
                    <input type="hidden" name="revoke_id" value="<?= (int) $account['id'] ?>">
                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Are you sure you want to revoke this account?');">Revoke</button>
                </form>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
        </table>
    </div>
</div>
</body>
</html>
