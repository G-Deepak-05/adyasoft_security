<?php
// dashboard/public/logout.php
declare(strict_types=1);

session_start();
require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Auth\SessionGuard;

SessionGuard::logout();
header('Location: /login.php');
