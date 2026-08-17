<?php
// dashboard/public/login.php
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

use AdyaSoft\Dashboard\Auth\Csrf;
use AdyaSoft\Dashboard\Auth\PasswordAuth;
use AdyaSoft\Dashboard\Auth\SessionGuard;
use AdyaSoft\Dashboard\Db\Connection;

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // A request without a valid CSRF token is rejected exactly like a failed
    // login, with the same generic message.
    if (!Csrf::check()) {
        $error = 'Invalid username or password.';
    } else {
        $config = require __DIR__ . '/../config/database.php';
        $pdo = Connection::create($config);
        $auth = new PasswordAuth($pdo);

        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $userId = $auth->verify($username, $password);

        if ($userId !== null) {
            SessionGuard::login($userId);
            header('Location: /index.php');
            exit;
        }

        $error = 'Invalid username or password.';
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Findings Dashboard — Login</title></head>
<body>
<?php if ($error !== null): ?>
    <p style="color:red;"><?= htmlspecialchars($error, ENT_QUOTES) ?></p>
<?php endif; ?>
<form method="post">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(Csrf::token(), ENT_QUOTES) ?>">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <button type="submit">Log in</button>
</form>
</body>
</html>
