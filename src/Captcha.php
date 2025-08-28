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
     * Constructor
     *
     * @param int $minSecretNumber Minimum secret number for challenge
     * @param int $maxSecretNumber Maximum secret number for challenge
     * @param Algorithm|string $algorithm Hash algorithm identifier
     * @throws InvalidArgumentException When algorithm is invalid
     */
    public function __construct(
        protected int    $minSecretNumber = 0,
        protected int    $maxSecretNumber = 1000000,
        protected Algorithm|string $algorithm = Algorithm::SHA256,
    ) {
        if (is_string($algorithm)) {
            $this->algorithm = Algorithm::tryFrom(strtolower($algorithm))
                ?? throw new InvalidArgumentException("Unsupported algorithm: {$algorithm}");
        }
    }

    /**
     * Verify a proof-of-work solution
     *
     * @param string $salt The salt used in the challenge
     * @param string $hash The expected hash
     * @param int $solution The proposed solution
     * @return bool True if solution is valid, false otherwise
     */
    public function verifySolution(string $salt, string $hash, int $solution): bool
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
        $generatedHash = hash_hmac($this->algorithm->value, (string)$solution, $salt);
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
     * Check validity of the challenge
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
     * @return array{algorithm: string, salt: string, hash: string} Challenge data
     */
    public function generateChallenge(): array
    {
        // Generate random salts
        $randomSalt = bin2hex(random_bytes(32)); // 64 characters
        $securedSalt = $this->secureSalt($randomSalt);
        // Generate random number
        $randomNumber = random_int($this->minSecretNumber, $this->maxSecretNumber);

        // Create hash
        $hash = hash_hmac($this->algorithm->value, (string)$randomNumber, $securedSalt);

        // Create challenge
        $challenge = [
            'algorithm' => $this->algorithm->value,
            'salt' => $securedSalt,
            'hash' => $hash,
        ];

        return $challenge;
    }

    /**
     * Secure the salt by upgrading it (stub implementation)
     *
     * @param string $salt The original salt
     * @return string The secured salt
     */
    protected function secureSalt(string $salt): string
    {
        return $salt;
    }
}
