<?php
// src/Detectors/UserDetector.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class UserDetector
{
    public function __construct(private readonly array $knownGoodUsernames)
    {
    }

    public function detect(array $currentUsers, array $previousScanUsers): array
    {
        $previousLogins = array_column($previousScanUsers, 'user_login');
        $findings = [];

        foreach ($currentUsers as $user) {
            if (!in_array($user['user_login'], $this->knownGoodUsernames, true)) {
                $findings[] = [
                    'type' => 'user_not_in_known_good_roster',
                    'user_login' => $user['user_login'],
                    'details' => $user,
                ];
            }

            if (!in_array($user['user_login'], $previousLogins, true)) {
                $findings[] = [
                    'type' => 'user_created_since_last_scan',
                    'user_login' => $user['user_login'],
                    'details' => $user,
                ];
            }
        }

        return $findings;
    }
}
