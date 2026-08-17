<?php
// config/scoring.php
declare(strict_types=1);

return [
    // signal_name => weight (points added to composite score when signal fires)
    'weights' => [
        'file_new' => 20,
        'file_modified' => 25,
        'file_deleted' => 10,
        'file_in_uploads_is_php' => 40,
        'file_in_mu_plugins_new' => 45,
        'core_file_checksum_mismatch' => 35,
        'core_file_not_in_manifest' => 35,
        'plugin_checksum_mismatch' => 30,
        'entropy_high' => 25,
        'entropy_obfuscation_pattern' => 30,
        'user_not_in_known_good_roster' => 50,
        'user_created_since_last_scan' => 30,
        'page_new' => 15,
        'page_modified' => 10,
        'page_unexpected_author' => 25,
        'htaccess_diff' => 30,
        'htaccess_external_redirect' => 35,
    ],
    // composite score (sum of fired signal weights) => severity band, evaluated high to low
    'severity_thresholds' => [
        'CRITICAL' => 70,
        'HIGH' => 45,
        'MEDIUM' => 20,
        'LOW' => 0,
    ],
];
