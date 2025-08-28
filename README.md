Lockbot
=======

Installation
------------

If you use Packagist for installing packages, then you can update your composer.json like this :

``` json
{
    "require": {
        "blackcube/lockbot": "*"
    }
}
```

Testing
-------

To run the tests:

``` bash
composer install
./vendor/bin/codecept build
./vendor/bin/codecept run
```

To check coverage report:

``` bash
./vendor/bin/codecept run --coverage --coverage-html
```

Usage
-----

Captcha class allows you to generate and verify POW CAPTCHA codes.

Generating CAPTCHA Codes

``` php
use blackcube\lockbot\Captcha;

$captcha = new Captcha();
$challenge = $captcha->generateChallenge(); // Generate a CAPTCHA challenge
// $challenge is an array with 'algorithm' and 'salt' and 'hash' keys
// ['algorithm' => 'sha256', 'salt' => 'random_salt', 'hash' => 'computed_hash']
```

Verifying CAPTCHA Codes

``` php
// $solution is the solution provided by the user ['salt' => 'challenge_salt', 'hash' => 'challenge_hash', 'algorithm' => 'challenge_algorithm', 'solution' => 'user_solution']
use blackcube\lockbot\Captcha;
$captcha = new Captcha(
    algorithm: $solution['algorithm'] // Use the same algorithm as the challenge);
);
$isValid = $captcha->verifySolution($solution['salt'], $solution['hash'], $solution['solution']); // Verify the provided solution
```

Main methods are:
- Generate a CAPTCHA challenge
- `generateChallenge(): array`
- Verify a provided solution
- `verifySolution(string $salt, string $hash, string $solution): bool`

Contributing
------------

All code contributions - including those of people having commit access -
must go through a pull request and approved by a core developer before being
merged. This is to ensure proper review of all the code.

Fork the project, create a [feature branch ](http://nvie.com/posts/a-successful-git-branching-model/), and send us a pull request.