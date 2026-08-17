<?php
// dashboard/bin/create-user.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Db\Connection;

$options = getopt('', ['username:', 'password:']);
if (!isset($options['username'], $options['password'])) {
    fwrite(STDERR, "Usage: php bin/create-user.php --username=<name> --password=<password>\n");
    exit(1);
}

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$hash = password_hash($options['password'], PASSWORD_BCRYPT);
$stmt = $pdo->prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)');
$stmt->execute([$options['username'], $hash, date('Y-m-d H:i:s')]);

fwrite(STDOUT, "User '{$options['username']}' created.\n");
