<?php
// dashboard/public/index.php
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
use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;
use AdyaSoft\Dashboard\Findings\FindingsPageController;
use AdyaSoft\Dashboard\Findings\FindingsRepository;

if (!SessionGuard::check()) {
    header('Location: /login.php');
    exit;
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$controller = new FindingsPageController(new FindingsRepository($pdo));
$viewModel = $controller->buildViewModel($_GET);
$accounts = (new AccountRepository($pdo))->all();

$pageLink = static function (int $targetPage): string {
    return '?' . http_build_query(array_merge($_GET, ['page' => $targetPage]));
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Findings Dashboard</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<div class="container">
    <nav class="navbar">
        <a href="/index.php" class="navbar-brand">🛡️ AdyaSoft Security</a>
        <div class="navbar-links">
            <a href="/accounts.php">Manage Accounts</a>
            <a href="/logout.php">Log out</a>
        </div>
    </nav>

    <div class="card" style="margin-bottom: 2rem;">
        <form method="get" class="filter-bar">
            <div class="form-group" style="margin-bottom: 0;">
                <label>Severity</label>
                <select name="severity[]" multiple>
                    <option value="CRITICAL" <?= in_array('CRITICAL', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>CRITICAL</option>
                    <option value="HIGH" <?= in_array('HIGH', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>HIGH</option>
                    <option value="MEDIUM" <?= in_array('MEDIUM', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>MEDIUM</option>
                    <option value="LOW" <?= in_array('LOW', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>LOW</option>
                </select>
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label>Account</label>
                <select name="account_id">
                    <option value="">All accounts</option>
                    <?php foreach ($accounts as $account): ?>
                    <option value="<?= (int) $account['id'] ?>" <?= (int) $account['id'] === (int) ($viewModel['filters']['account_id'] ?? 0) ? 'selected' : '' ?>><?= htmlspecialchars((string) $account['name'], ENT_QUOTES) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label>Site ID</label>
                <input type="text" name="site_id" value="<?= htmlspecialchars((string) ($viewModel['filters']['site_id'] ?? ''), ENT_QUOTES) ?>">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label>Type(s), comma-separated</label>
                <input type="text" name="type_filter" value="<?= htmlspecialchars(implode(', ', $viewModel['filters']['type']), ENT_QUOTES) ?>">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label>From</label>
                <input type="date" name="from" value="<?= htmlspecialchars((string) ($viewModel['filters']['from'] ?? ''), ENT_QUOTES) ?>">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label>To</label>
                <input type="date" name="to" value="<?= htmlspecialchars((string) ($viewModel['filters']['to'] ?? ''), ENT_QUOTES) ?>">
            </div>
            <button type="submit" class="btn btn-auto">Filter</button>
        </form>
    </div>

    <div class="table-container">
        <table>
        <thead><tr><th>Severity</th><th>Site</th><th>Type</th><th>Subject</th><th>Score</th><th>Scanned At</th></tr></thead>
        <tbody>
        <?php foreach ($viewModel['rows'] as $row): ?>
        <tr>
            <td>
                <?php
                $sev = strtolower(htmlspecialchars($row['severity'], ENT_QUOTES));
                echo '<span class="badge badge-' . $sev . '">' . strtoupper($sev) . '</span>';
                ?>
            </td>
            <td><?= htmlspecialchars($row['site_label'] ?? $row['site_id'], ENT_QUOTES) ?></td>
            <td><code><?= htmlspecialchars($row['finding_type'], ENT_QUOTES) ?></code></td>
            <td><?= htmlspecialchars($row['subject'], ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars((string) $row['composite_score'], ENT_QUOTES) ?></td>
            <td><?= htmlspecialchars($row['scanned_at'], ENT_QUOTES) ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
        </table>
    </div>

    <?php $totalPages = max(1, (int) $viewModel['totalPages']); ?>
    <div class="pagination">
        <?php if ((int) $viewModel['page'] > 1): ?>
        <a href="<?= htmlspecialchars($pageLink((int) $viewModel['page'] - 1), ENT_QUOTES) ?>">&laquo; Previous</a>
        <?php endif; ?>
        <span>Page <?= (int) $viewModel['page'] ?> of <?= $totalPages ?> (<?= (int) $viewModel['total'] ?> total findings)</span>
        <?php if ((int) $viewModel['page'] < $totalPages): ?>
        <a href="<?= htmlspecialchars($pageLink((int) $viewModel['page'] + 1), ENT_QUOTES) ?>">Next &raquo;</a>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
