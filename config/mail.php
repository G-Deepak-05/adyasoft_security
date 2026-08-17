<?php
// config/mail.php
declare(strict_types=1);

return [
    'from' => 'security-scanner@example.com',
    'to' => ['security-ops@example.com'],
    'alert_on_bands' => ['CRITICAL', 'HIGH'],
    'digest_hour_utc' => 6,
];
