<?php
// dashboard/public/ingest.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Db\Connection;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Ingest\IngestController;
use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;

$config = require __DIR__ . '/../config/database.php';
$pdo = Connection::create($config);

$controller = new IngestController(
    new ApiKeyAuthenticator($pdo),
    new IngestPayloadValidator(),
    new FindingsIngester($pdo),
);

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
$rawBody = file_get_contents('php://input');

$result = $controller->handle($authHeader, $rawBody);

http_response_code($result['status']);
header('Content-Type: application/json');
echo $result['body'];
