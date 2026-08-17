<?php
// dashboard/public/ingest.php
declare(strict_types=1);

require __DIR__ . '/../src/Autoload/autoload.php';

use AdyaSoft\Dashboard\Accounts\ApiKeyAuthenticator;
use AdyaSoft\Dashboard\Db\Connection;
use AdyaSoft\Dashboard\Ingest\FindingsIngester;
use AdyaSoft\Dashboard\Ingest\IngestController;
use AdyaSoft\Dashboard\Ingest\IngestPayloadValidator;

/**
 * Read the Authorization header.
 *
 * Apache/LiteSpeed running PHP as CGI/FastCGI (i.e. typical hPanel hosting)
 * commonly strips this header before PHP sees it. public/.htaccess re-exposes
 * it, but depending on the server config it can land under either
 * HTTP_AUTHORIZATION or REDIRECT_HTTP_AUTHORIZATION — and on some setups only
 * apache_request_headers()/getallheaders() has it. Try each in turn.
 */
function dashboard_authorization_header(): ?string
{
    foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $key) {
        if (isset($_SERVER[$key]) && $_SERVER[$key] !== '') {
            return (string) $_SERVER[$key];
        }
    }

    $headersFn = null;
    if (function_exists('apache_request_headers')) {
        $headersFn = 'apache_request_headers';
    } elseif (function_exists('getallheaders')) {
        $headersFn = 'getallheaders';
    }

    if ($headersFn !== null) {
        $headers = $headersFn();
        if (is_array($headers)) {
            foreach ($headers as $name => $value) {
                if (strcasecmp((string) $name, 'Authorization') === 0 && $value !== '') {
                    return (string) $value;
                }
            }
        }
    }

    return null;
}

try {
    $config = require __DIR__ . '/../config/database.php';
    $pdo = Connection::create($config);

    $controller = new IngestController(
        new ApiKeyAuthenticator($pdo),
        new IngestPayloadValidator(),
        new FindingsIngester($pdo),
    );

    $authHeader = dashboard_authorization_header();
    $rawBody = file_get_contents('php://input');

    $result = $controller->handle($authHeader, $rawBody);

    http_response_code($result['status']);
    header('Content-Type: application/json');
    echo $result['body'];
} catch (\Throwable $e) {
    // Defense in depth: never let an ingest failure surface as a raw PHP fatal.
    // The message is deliberately generic — this caller may be unauthenticated,
    // so no exception detail may leak into the response.
    http_response_code(500);
    header('Content-Type: application/json');
    echo '{"status":"error","message":"internal error"}';
}
