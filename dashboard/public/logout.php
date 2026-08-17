<?php
// dashboard/public/logout.php
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

use AdyaSoft\Dashboard\Auth\SessionGuard;

SessionGuard::logout();
// Clear the server-side session data too, not just the individual keys.
session_destroy();
header('Location: /login.php');
