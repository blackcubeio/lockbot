<?php
/**
 * Captcha.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@gmail.com>
 * @copyright 2010-2025 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

declare(strict_types=1);

namespace blackcube\lockbot;

use InvalidArgumentException;

/**
 * Class Captcha
 *
 * Proof of Work CAPTCHA implementation
 *
 * This class provides methods to generate and validate proof-of-work challenges
 *
 * @author Philippe Gaultier <pgaultier@gmail.com>
 * @copyright 2010-2025 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class Captcha
{
    /**
     * Available algorithms mapping
     *
     * @var array<string>
     */
    private array $algorithmMapping = [
        'SHA-1' => 'sha1',
        'SHA-256' => 'sha256',
        'SHA-384' => 'sha384',
        'SHA-512' => 'sha512',
    ];

    /**
     * Constructor
     *
     * @param int $expired Challenge expiration time in seconds
     * @param int $minSecretNumber Minimum secret number for challenge
     * @param int $maxSecretNumber Maximum secret number for challenge
     * @param string $algorithm Hash algorithm identifier
     */
    public function __construct(
        protected int    $expired = 120,
        protected int    $minSecretNumber = 0,
        protected int    $maxSecretNumber = 1000000,
        protected string $algorithm = 'SHA-256',
    ) {
        // Validate and set algorithm
        if (isset($this->algorithmMapping[$this->algorithm])) {
            $this->algorithm = $this->algorithmMapping[$this->algorithm];
        } else {
            throw new InvalidArgumentException('Unsupported algorithm: ' . $this->algorithm);
        }
    }

    /**
     * Verify a proof-of-work solution
     *
     * @param string $key TOTP key identifier
     * @param string $salt The salt used in the challenge
     * @param string $hash The expected hash
     * @param int $solution The proposed solution
     * @return bool True if solution is valid, false otherwise
     */
    public function verifySolution(string $key, string $salt, string $hash, int $solution): bool
    {
        $antiReplay = $this->antiReplay($hash);
        if (!$antiReplay) {
            return false;
        }
        $validity = $this->preCheckValidity($salt);
        if (!$validity) {
            return false;
        }
        // Verify the hash
        $generatedHash = hash_hmac($this->algorithm, (string)$solution, $salt);
        return hash_equals($generatedHash, $hash);
    }

    /**
     * Anti-replay mechanism (stub implementation)
     *
     * @param string $hash The expected hash
     * @return bool True if the hash has not been used before, false otherwise
     */
    protected function antiReplay(string $hash): bool
    {
        return true;
    }

    /**
     * Check validity of the challenge (e.g., TOTP code)
     *
     * @param string $salt The salt used in the challenge
     * @return bool True if challenge is still valid, false otherwise
     */
    protected function preCheckValidity(string $salt): bool
    {
        return true;
    }

    /**
     * Generate a new proof-of-work challenge
     *
     * @param string $key TOTP key identifier
     * @return array{algorithm: string, salt: string, hash: string} Challenge data
     */
    public function generateChallenge(string $key): array
    {
        // Generate random salts
        $randomSalt = bin2hex(random_bytes(32)); // 64 characters
        $securedSalt = $this->secureSalt($randomSalt);
        // Generate random number
        $randomNumber = random_int($this->minSecretNumber, $this->maxSecretNumber);

        // Create hash
        $hash = hash_hmac($this->algorithm, (string)$randomNumber, $securedSalt);

        // Create challenge
        $challenge = [
            'algorithm' => $this->algorithm,
            'salt' => $securedSalt,
            'hash' => $hash,
        ];

        return $challenge;
    }

    /**
     * Secure the salt by embedding stuff (stub implementation)
     *
     * @param string $salt The original salt
     * @return string The secured salt
     */
    protected function secureSalt(string $salt): string
    {
        return $salt;
    }
}
