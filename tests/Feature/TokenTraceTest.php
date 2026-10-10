<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedCriticalHeader;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/*
 * A bearer token is a credential: whoever holds it is the user (or the calling
 * service) until it expires. Wherever `zend.exception_ignore_args` is off, every
 * frame of an exception keeps its call arguments, and error trackers and debug
 * dumps show them. So a verify that throws below the manager must not leave the
 * token in any frame — of the exception or of any exception it wraps.
 */

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'jwt.service.secret' => 'a-very-secret-service-key-0123456789',
        'jwt.service.issuer' => 'web',
        'app.service' => 'web',
        'auth.guards.api' => ['driver' => 'jwt'],
        'auth.guards.internal' => ['driver' => 'service-jwt'],
    ]);

    // A dev-style ini: call arguments kept in the trace, strings not cut at 15 bytes.
    $this->ignoreArgs = ini_set('zend.exception_ignore_args', '0');
    $this->maxLength = ini_set('zend.exception_string_param_max_len', '1000000');

    // A well-formed RS256 token whose signature no key produced.
    [$header, $payload] = explode('.', app(JwtManager::class)->mintAccessToken(AccessTokenRequest::for('user-1'))->token);
    $this->forged = $header.'.'.$payload.'.'.Base64Url::encode(str_repeat("\x5a", 256));

    // A token the header policy refuses before any signature work.
    $this->critical = Base64Url::encode('{"typ":"JWT","alg":"RS256","crit":["exp"]}').'.'.$payload.'.'.Base64Url::encode('signature');

    /*
     * Calls $call and returns what an error tracker could read from the thrown
     * chain: every scalar among the frame arguments, and how many arguments were
     * redacted (a count above zero proves the frames kept their arguments).
     *
     * @return array{0: class-string<Throwable>, 1: string, 2: int}
     */
    $this->exposed = static function (Closure $call): array {
        try {
            $call();
        } catch (Throwable $e) {
            $seen = [];
            $redacted = 0;
            $collect = static function (mixed $value) use (&$collect, &$seen, &$redacted): void {
                if (is_array($value)) {
                    array_walk($value, $collect);
                } elseif ($value instanceof SensitiveParameterValue) {
                    $redacted++;
                } elseif (is_scalar($value)) {
                    $seen[] = (string) $value;
                }
            };

            for ($current = $e; $current !== null; $current = $current->getPrevious()) {
                foreach ($current->getTrace() as $frame) {
                    $collect($frame['args'] ?? []);
                }
            }

            return [$e::class, implode("\n", $seen), $redacted];
        }

        throw new RuntimeException('The call did not throw.');
    };
});

afterEach(function (): void {
    ini_set('zend.exception_ignore_args', (string) $this->ignoreArgs);
    ini_set('zend.exception_string_param_max_len', (string) $this->maxLength);
    CarbonImmutable::setTestNow();
});

it('keeps a forged user token out of every frame of the manager verify', function (): void {
    $token = $this->forged;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => app(JwtManager::class)->verify($token, 'web'));

    expect($class)->toBe(InvalidSignature::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps a refused header out of every frame of the manager verify', function (): void {
    $token = $this->critical;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => app(JwtManager::class)->verify($token));

    expect($class)->toBe(UnexpectedCriticalHeader::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps the token out of every frame of a guard verify', function (): void {
    $token = $this->forged;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => app(JwtManager::class)->guard('api')->verify($token));

    expect($class)->toBe(InvalidSignature::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps the token out of every frame when the jwt guard validates against a missing key', function (): void {
    config(['jwt.public_key_path' => fixturesDir().'/keys/missing.pem']);
    app()->forgetInstance(KeyRepository::class);
    app()->forgetInstance(UserTokenVerifier::class);
    $token = $this->forged;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => Auth::guard('api')->validate(['token' => $token]));

    expect($class)->toBe(KeyLoadFailed::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps a service token out of every frame when the shared secret is missing', function (): void {
    config(['jwt.service.secret' => null]);
    $token = $this->forged;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => app(JwtManager::class)->services()->verify($token));

    expect($class)->toBe(ServiceAuthMisconfigured::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps a service token out of every frame when its issuer cannot be read', function (): void {
    config(['jwt.service.secrets' => 'billing:a-very-secret-billing-key-0123456789']);
    [$header, , $signature] = explode('.', $this->critical);
    $token = $header.'.'.Base64Url::encode('not json').'.'.$signature;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => app(JwtManager::class)->services()->verify($token));

    expect($class)->toBe(MalformedToken::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});

it('keeps the token out of every frame when the service guard validates without a secret', function (): void {
    config(['jwt.service.secret' => null]);
    $token = $this->forged;

    [$class, $frames, $redacted] = ($this->exposed)(fn () => Auth::guard('internal')->validate(['token' => $token]));

    expect($class)->toBe(ServiceAuthMisconfigured::class)
        ->and($frames)->not->toContain($token)
        ->and($redacted)->toBeGreaterThan(0);
});
