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
<html>
<head><title>Findings Dashboard</title></head>
<body>
<p><a href="/accounts.php">Manage accounts</a> | <a href="/logout.php">Log out</a></p>
<form method="get">
    <label>Severity:
        <select name="severity[]" multiple>
            <option value="CRITICAL" <?= in_array('CRITICAL', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>CRITICAL</option>
            <option value="HIGH" <?= in_array('HIGH', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>HIGH</option>
            <option value="MEDIUM" <?= in_array('MEDIUM', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>MEDIUM</option>
            <option value="LOW" <?= in_array('LOW', $viewModel['filters']['severity'], true) ? 'selected' : '' ?>>LOW</option>
        </select>
    </label>
    <label>Account:
        <select name="account_id">
            <option value="">All accounts</option>
            <?php foreach ($accounts as $account): ?>
            <option value="<?= (int) $account['id'] ?>" <?= (int) $account['id'] === (int) ($viewModel['filters']['account_id'] ?? 0) ? 'selected' : '' ?>><?= htmlspecialchars((string) $account['name'], ENT_QUOTES) ?></option>
            <?php endforeach; ?>
        </select>
    </label>
    <label>Site ID: <input type="text" name="site_id" value="<?= htmlspecialchars((string) ($viewModel['filters']['site_id'] ?? ''), ENT_QUOTES) ?>"></label>
    <label>Type(s), comma-separated: <input type="text" name="type_filter" value="<?= htmlspecialchars(implode(', ', $viewModel['filters']['type']), ENT_QUOTES) ?>"></label>
    <label>From: <input type="date" name="from" value="<?= htmlspecialchars((string) ($viewModel['filters']['from'] ?? ''), ENT_QUOTES) ?>"></label>
    <label>To: <input type="date" name="to" value="<?= htmlspecialchars((string) ($viewModel['filters']['to'] ?? ''), ENT_QUOTES) ?>"></label>
    <button type="submit">Filter</button>
</form>
<table border="1">
<thead><tr><th>Severity</th><th>Site</th><th>Type</th><th>Subject</th><th>Score</th><th>Scanned At</th></tr></thead>
<tbody>
<?php foreach ($viewModel['rows'] as $row): ?>
<tr>
    <td><?= htmlspecialchars($row['severity'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['site_label'] ?? $row['site_id'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['finding_type'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['subject'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars((string) $row['composite_score'], ENT_QUOTES) ?></td>
    <td><?= htmlspecialchars($row['scanned_at'], ENT_QUOTES) ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php $totalPages = max(1, (int) $viewModel['totalPages']); ?>
<p>
    <?php if ((int) $viewModel['page'] > 1): ?>
    <a href="<?= htmlspecialchars($pageLink((int) $viewModel['page'] - 1), ENT_QUOTES) ?>">&laquo; Previous</a>
    <?php endif; ?>
    Page <?= (int) $viewModel['page'] ?> of <?= $totalPages ?> (<?= (int) $viewModel['total'] ?> total findings)
    <?php if ((int) $viewModel['page'] < $totalPages): ?>
    <a href="<?= htmlspecialchars($pageLink((int) $viewModel['page'] + 1), ENT_QUOTES) ?>">Next &raquo;</a>
    <?php endif; ?>
</p>
</body>
</html>
