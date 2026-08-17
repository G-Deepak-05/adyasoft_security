<?php
// src/Detectors/EntropyAnalyzer.php
declare(strict_types=1);

namespace AdyaSoft\Security\Detectors;

final class EntropyAnalyzer
{
    private const OBFUSCATION_PATTERNS = [
        '/eval\s*\(\s*base64_decode\s*\(/i',
        '/eval\s*\(\s*gzinflate\s*\(/i',
        '/eval\s*\(\s*gzuncompress\s*\(/i',
        '/eval\s*\(\s*str_rot13\s*\(/i',
        '/assert\s*\(\s*(?:\$|[\'"])/i',
        '/create_function\s*\(/i',
        '/\$\$[a-zA-Z_]/',
        '/call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/i',
    ];

    public function __construct(
        private readonly float $entropyThreshold = 4.5,
        private readonly int $minStringLength = 40,
    ) {
    }

    public function analyzeFile(string $absolutePath): array
    {
        $source = file_get_contents($absolutePath);
        if ($source === false) {
            return [];
        }

        $findings = [];

        if ($this->hasHighEntropyStringLiteral($source)) {
            $findings[] = ['type' => 'entropy_high', 'path' => $absolutePath, 'details' => []];
        }

        foreach (self::OBFUSCATION_PATTERNS as $pattern) {
            if (preg_match($pattern, $source) === 1) {
                $findings[] = ['type' => 'entropy_obfuscation_pattern', 'path' => $absolutePath, 'details' => ['pattern' => $pattern]];
                break; // one finding per file is enough signal; details carries which pattern
            }
        }

        return $findings;
    }

    private function hasHighEntropyStringLiteral(string $source): bool
    {
        $tokens = @token_get_all($source);
        if (!is_array($tokens)) {
            return false;
        }

        foreach ($tokens as $token) {
            if (!is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }
            $literal = stripslashes(substr($token[1], 1, -1));
            if (strlen($literal) >= $this->minStringLength && $this->shannonEntropy($literal) >= $this->entropyThreshold) {
                return true;
            }
        }

        return false;
    }

    private function shannonEntropy(string $data): float
    {
        $length = strlen($data);
        if ($length === 0) {
            return 0.0;
        }

        $frequencies = array_count_values(str_split($data));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }
}
