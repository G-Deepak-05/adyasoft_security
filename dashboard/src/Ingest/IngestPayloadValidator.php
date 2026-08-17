<?php
// dashboard/src/Ingest/IngestPayloadValidator.php
declare(strict_types=1);

namespace AdyaSoft\Dashboard\Ingest;

final class IngestPayloadValidator
{
    private const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

    public function validate(array $payload): array
    {
        $errors = [];

        if (!isset($payload['meta']) || !is_array($payload['meta'])) {
            $errors[] = 'meta is required and must be an object';
        } else {
            foreach (['site_id', 'scan_id', 'scanned_at'] as $key) {
                if (!isset($payload['meta'][$key]) || !is_string($payload['meta'][$key]) || $payload['meta'][$key] === '') {
                    $errors[] = "meta.{$key} is required and must be a non-empty string";
                }
            }
        }

        if (!isset($payload['findings']) || !is_array($payload['findings'])) {
            $errors[] = 'findings is required and must be an array';
        } else {
            foreach ($payload['findings'] as $index => $group) {
                if (!is_array($group)) {
                    $errors[] = "findings[{$index}] must be an object";
                    continue;
                }

                foreach (['subject', 'severity', 'composite_score', 'findings'] as $key) {
                    if (!array_key_exists($key, $group)) {
                        $errors[] = "findings[{$index}].{$key} is required";
                    }
                }

                // severity maps to a MySQL ENUM and composite_score to an INT in
                // production; reject bad values here with a clean 400 rather than
                // letting them become a data-truncation error at INSERT time.
                if (array_key_exists('severity', $group)
                    && (!is_string($group['severity']) || !in_array($group['severity'], self::VALID_SEVERITIES, true))
                ) {
                    $errors[] = "findings[{$index}].severity must be one of "
                        . implode(', ', self::VALID_SEVERITIES);
                }

                if (array_key_exists('composite_score', $group) && !is_numeric($group['composite_score'])) {
                    $errors[] = "findings[{$index}].composite_score must be numeric";
                }

                if (isset($group['findings']) && is_array($group['findings'])) {
                    foreach ($group['findings'] as $j => $individual) {
                        if (!is_array($individual) || !isset($individual['type'])) {
                            $errors[] = "findings[{$index}].findings[{$j}].type is required";
                        }
                    }
                }
            }
        }

        return ['valid' => $errors === [], 'errors' => $errors];
    }
}
