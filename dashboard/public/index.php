<?php
// dashboard/public/index.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

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
<p>Page <?= (int) $viewModel['page'] ?> of <?= max(1, (int) $viewModel['totalPages']) ?> (<?= (int) $viewModel['total'] ?> total findings)</p>
</body>
</html>
