<?php
// tests/Detectors/UserDetectorTest.php
declare(strict_types=1);

namespace AdyaSoft\Security\Tests\Detectors;

use AdyaSoft\Security\Detectors\UserDetector;
use PHPUnit\Framework\TestCase;

final class UserDetectorTest extends TestCase
{
    private function user(string $login): array
    {
        return ['id' => 1, 'user_login' => $login, 'user_email' => "{$login}@example.com", 'user_registered' => '2024-01-01', 'roles' => ['administrator']];
    }

    public function testFlagsUserNotInKnownGoodRoster(): void
    {
        $detector = new UserDetector(['boss']);

        $findings = $detector->detect([$this->user('boss'), $this->user('rogue')], [$this->user('boss'), $this->user('rogue')]);

        $types = array_column($findings, 'type');
        $this->assertContains('user_not_in_known_good_roster', $types);
        $rogueFinding = array_values(array_filter($findings, fn ($f) => $f['user_login'] === 'rogue'))[0];
        $this->assertSame('user_not_in_known_good_roster', $rogueFinding['type']);

        // Assert rogue does NOT produce user_created_since_last_scan (it existed in previous scan)
        $rogueFindings = array_column(
            array_filter($findings, fn ($f) => $f['user_login'] === 'rogue'),
            'type'
        );
        $this->assertNotContains('user_created_since_last_scan', $rogueFindings);
    }

    public function testFlagsUserCreatedSincePreviousScanEvenIfKnownGood(): void
    {
        $detector = new UserDetector(['boss', 'newadmin']);

        $findings = $detector->detect(
            [$this->user('boss'), $this->user('newadmin')],
            [$this->user('boss')], // newadmin wasn't present last scan
        );

        $newAdminFindings = array_column(
            array_filter($findings, fn ($f) => $f['user_login'] === 'newadmin'),
            'type'
        );
        $this->assertContains('user_created_since_last_scan', $newAdminFindings);
        $this->assertNotContains('user_not_in_known_good_roster', $newAdminFindings);
    }

    public function testNoFindingsForKnownExistingUser(): void
    {
        $detector = new UserDetector(['boss']);

        $findings = $detector->detect([$this->user('boss')], [$this->user('boss')]);

        $this->assertSame([], $findings);
    }

    public function testFlagsBothFindingsForUnapprovedNewUser(): void
    {
        $detector = new UserDetector(['boss']);

        // 'attacker' is both NOT in known-good roster AND NOT in previous scan
        // This is the highest-severity case: a brand-new, unapproved admin account
        $findings = $detector->detect(
            [$this->user('boss'), $this->user('attacker')],
            [$this->user('boss')], // attacker wasn't present last scan
        );

        $attackerFindings = array_column(
            array_filter($findings, fn ($f) => $f['user_login'] === 'attacker'),
            'type'
        );
        $this->assertContains('user_not_in_known_good_roster', $attackerFindings);
        $this->assertContains('user_created_since_last_scan', $attackerFindings);
    }
}
