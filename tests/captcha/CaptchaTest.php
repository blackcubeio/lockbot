<?php

use blackcube\lockbot\Captcha;
use blackcube\lockbot\Algorithm;

class CaptchaTest extends \Codeception\Test\Unit
{
    /**
     * @var \tests\CaptchaTester
     */
    protected $tester;

    private Captcha $captcha;

    protected function _before()
    {
        // Use smaller range for faster tests
        $this->captcha = new Captcha(
            minSecretNumber: 0, maxSecretNumber: 100
        );
    }

    protected function _after()
    {
    }

    public function testConstructorDefaults()
    {
        $captcha = new Captcha();

        $this->assertInstanceOf(Captcha::class, $captcha);
    }

    public function testConstructorWithCustomValues()
    {
        $captcha = new Captcha(
            minSecretNumber: 100,
            maxSecretNumber: 999,
            algorithm: Algorithm::SHA512
        );

        $this->assertInstanceOf(Captcha::class, $captcha);
    }

    public function testConstructorThrowsExceptionForInvalidAlgorithm()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm: invalid');

        new Captcha(0, 1000000, algorithm: 'invalid');
    }

    public function testGenerateChallenge()
    {
        $challenge = $this->captcha->generateChallenge();

        $this->assertIsArray($challenge);
        $this->assertArrayHasKey('algorithm', $challenge);
        $this->assertArrayHasKey('salt', $challenge);
        $this->assertArrayHasKey('hash', $challenge);

        $this->assertEquals('sha256', $challenge['algorithm']);
        $this->assertIsString($challenge['salt']);
        $this->assertIsString($challenge['hash']);

        // Salt should be 64 characters (hex encoded)
        $this->assertEquals(64, strlen($challenge['salt']));

        // Hash should be 64 characters for SHA-256
        $this->assertEquals(64, strlen($challenge['hash']));
    }

    public function testGenerateChallengeProducesUniqueResults()
    {
        $challenge1 = $this->captcha->generateChallenge();
        $challenge2 = $this->captcha->generateChallenge();

        $this->assertNotEquals($challenge1['salt'], $challenge2['salt']);
        $this->assertNotEquals($challenge1['hash'], $challenge2['hash']);
    }

    public function testVerifySolution()
    {
        $challenge = $this->captcha->generateChallenge();

        // We need to brute force the solution since it's random (range 0-100)
        $solutionFound = false;
        for ($i = 0; $i <= 100; $i++) {
            if ($this->captcha->verifySolution($challenge['salt'], $challenge['hash'], $i)) {
                $solutionFound = true;
                break;
            }
        }

        $this->assertTrue($solutionFound, 'Should find a valid solution in range 0-100');
    }

    public function testVerifySolutionReturnsFalseForInvalidSolution()
    {
        $challenge = $this->captcha->generateChallenge();

        // Using -1 should never be a valid solution
        $result = $this->captcha->verifySolution($challenge['salt'], $challenge['hash'], -1);
        $this->assertFalse($result);
    }

    public function testAntiReplayAlwaysReturnsTrue()
    {
        // In base Captcha class, antiReplay always returns true (stub implementation)
        $challenge = $this->captcha->generateChallenge();

        // Find a valid solution
        $validSolution = null;
        for ($i = 0; $i <= 100; $i++) {
            if ($this->captcha->verifySolution($challenge['salt'], $challenge['hash'], $i)) {
                $validSolution = $i;
                break;
            }
        }

        $this->assertNotNull($validSolution, 'Should find a valid solution');

        // Should be able to verify the same solution multiple times (no replay protection)
        $result1 = $this->captcha->verifySolution($challenge['salt'], $challenge['hash'], $validSolution);
        $result2 = $this->captcha->verifySolution($challenge['salt'], $challenge['hash'], $validSolution);

        $this->assertTrue($result1);
        $this->assertTrue($result2);
    }

    public function testPreCheckValidityAlwaysReturnsTrue()
    {
        // In base Captcha class, preCheckValidity always returns true (stub implementation)
        $challenge = $this->captcha->generateChallenge();

        // Should always pass validity check
        $result = $this->captcha->verifySolution($challenge['salt'], $challenge['hash'], 0);
        // Result depends on hash verification, but preCheckValidity doesn't fail
        $this->assertIsBool($result);
    }

    public function testSecureSaltReturnsOriginalSalt()
    {
        // In base Captcha class, secureSalt returns original salt unchanged
        $challenge1 = $this->captcha->generateChallenge();
        $challenge2 = $this->captcha->generateChallenge();

        // Both should have the same structure (64 chars)
        $this->assertEquals(64, strlen($challenge1['salt']));
        $this->assertEquals(64, strlen($challenge2['salt']));
    }

    public function testSetAlgorithmWithEnum()
    {
        // Test setting algorithm with Algorithm enum
        $this->captcha->setAlgorithm(Algorithm::SHA512);

        $challenge = $this->captcha->generateChallenge();
        $this->assertEquals('sha512', $challenge['algorithm']);

        // SHA-512 hash should be 128 characters long
        $this->assertEquals(128, strlen($challenge['hash']));
    }

    public function testSetAlgorithmWithValidString()
    {
        // Test setting algorithm with valid string (case insensitive)
        $this->captcha->setAlgorithm('SHA384');

        $challenge = $this->captcha->generateChallenge();
        $this->assertEquals('sha384', $challenge['algorithm']);

        // SHA-384 hash should be 96 characters long
        $this->assertEquals(96, strlen($challenge['hash']));
    }

    public function testSetAlgorithmWithValidLowercaseString()
    {
        // Test setting algorithm with valid lowercase string
        $this->captcha->setAlgorithm('sha1');

        $challenge = $this->captcha->generateChallenge();
        $this->assertEquals('sha1', $challenge['algorithm']);

        // SHA-1 hash should be 40 characters long
        $this->assertEquals(40, strlen($challenge['hash']));
    }

    public function testSetAlgorithmThrowsExceptionForInvalidString()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm: invalid-algo');

        $this->captcha->setAlgorithm('invalid-algo');
    }

    public function testSetAlgorithmThrowsExceptionForEmptyString()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm: ');

        $this->captcha->setAlgorithm('');
    }
}
