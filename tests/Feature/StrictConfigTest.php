<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\JwtServiceProvider;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/**
 * Regression (strict config sweep): the shipped config cast both switches with
 * `(bool) env(...)`, so `JWT_CHECK_DENYLIST=off` read as true and a typo such as
 * `JWT_AUTHORIZE_FROM_CLAIMS=disabled` silently switched claim authorization ON.
 * The config file now hands the raw env string to the strict reader.
 */
dataset('jwt env switches', [
    'JWT_CHECK_DENYLIST' => ['JWT_CHECK_DENYLIST'],
    'JWT_AUTHORIZE_FROM_CLAIMS' => ['JWT_AUTHORIZE_FROM_CLAIMS'],
]);

/**
 * @return array<string, mixed>
 */
function shippedJwtConfig(string $env, string $value): array
{
    $_SERVER[$env] = $value;

    try {
        /** @var array<string, mixed> $config */
        $config = require __DIR__.'/../../config/jwt.php';
    } finally {
        unset($_SERVER[$env]);
    }

    return $config;
}

it('hands the raw env string to the strict reader (strict config)', function (string $env): void {
    $config = shippedJwtConfig($env, 'disabled');

    $value = $env === 'JWT_CHECK_DENYLIST' ? $config['guard']['check_denylist'] : $config['authorize_from_claims'];

    expect($value)->toBe('disabled');
})->with('jwt env switches');

it('keeps the shipped switch defaults as real booleans', function (): void {
    /** @var array{guard: array{check_denylist: mixed}, authorize_from_claims: mixed} $config */
    $config = require __DIR__.'/../../config/jwt.php';

    expect($config['guard']['check_denylist'])->toBeTrue()
        ->and($config['authorize_from_claims'])->toBeFalse();
});

it('reads an env-style "off" denylist switch from the shipped config as off', function (): void {
    config(['jwt.guard.check_denylist' => shippedJwtConfig('JWT_CHECK_DENYLIST', 'off')['guard']['check_denylist']]);

    Artisan::call('about --only=jwt');

    expect(Artisan::output())->toMatch('/Denylist check\s*\.*\s*OFF/');
});

it('refuses a typo in the claim authorization switch when the provider boots (strict config)', function (): void {
    config(['jwt.authorize_from_claims' => 'disabled']);

    $provider = new JwtServiceProvider($this->app);

    expect(fn () => (fn () => $this->registerClaimAuthorization())->call($provider))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [jwt.authorize_from_claims] must be a boolean (true/false, 1/0, on/off or yes/no), [disabled] given.');
});

it('refuses a typo in either switch in the about section (strict config)', function (string $key): void {
    config([$key => 'disabled']);

    expect(fn () => Artisan::call('about --only=jwt'))->toThrow(JwtMisconfigured::class, "[{$key}]");
})->with(['jwt.guard.check_denylist', 'jwt.authorize_from_claims']);

it('hands raw env integers to the strict reader (strict config)', function (string $env, string $path): void {
    $config = shippedJwtConfig($env, 'five');

    expect(data_get($config, $path))->toBe('five');
})->with([
    'JWT_TTL' => ['JWT_TTL', 'ttl'],
    'JWT_CHALLENGE_TTL' => ['JWT_CHALLENGE_TTL', 'challenge_ttl'],
    'JWT_VERIFY_TTL' => ['JWT_VERIFY_TTL', 'verify_ttl'],
    'JWT_LEEWAY' => ['JWT_LEEWAY', 'leeway'],
    'SERVICE_JWT_TTL' => ['SERVICE_JWT_TTL', 'service.ttl'],
]);

it('refuses a junk or out-of-range integer instead of reading it as 0 (strict config)', function (string $key, mixed $junk, string $service): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.denylist.store' => 'array',
        $key => $junk,
    ]);

    expect(fn () => app($service))->toThrow(JwtMisconfigured::class, "Configuration value [{$key}]");
})->with([
    'ttl word' => ['jwt.ttl', 'five', UserTokenIssuer::class],
    'ttl zero' => ['jwt.ttl', 0, UserTokenIssuer::class],
    'challenge ttl float string' => ['jwt.challenge_ttl', '1.5', UserTokenIssuer::class],
    'verify ttl blank' => ['jwt.verify_ttl', '', UserTokenIssuer::class],
    'leeway junk' => ['jwt.leeway', '10s', UserTokenVerifier::class],
    'leeway negative' => ['jwt.leeway', -1, UserTokenVerifier::class],
    'denylist leeway junk' => ['jwt.leeway', 'ten', Denylist::class],
    'service ttl junk' => ['jwt.service.ttl', 'a minute', NativeServiceTokenService::class],
]);

it('uses the shipped defaults for absent integers (strict config)', function (): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.ttl' => null,
        'jwt.challenge_ttl' => null,
        'jwt.verify_ttl' => null,
        'jwt.leeway' => '0',
    ]);

    expect(app(UserTokenIssuer::class))->toBeInstanceOf(UserTokenIssuer::class)
        ->and(app(UserTokenVerifier::class))->toBeInstanceOf(UserTokenVerifier::class);
});

it('refuses a mistyped string or list setting instead of using the default (strict config)', function (string $key, mixed $junk, string $service): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.denylist.store' => 'array',
        $key => $junk,
    ]);

    expect(fn () => app($service))->toThrow(JwtMisconfigured::class, "Configuration value [{$key}]");
})->with([
    'issuers not a list' => ['jwt.service.issuers', 'billing,api', NativeServiceTokenService::class],
    'issuers non-string entry' => ['jwt.service.issuers', ['billing', 42], NativeServiceTokenService::class],
    'issuers blank entry' => ['jwt.service.issuers', ['billing', ' '], NativeServiceTokenService::class],
    'denylist prefix blank' => ['jwt.denylist.prefix', '', Denylist::class],
    'denylist store not a string' => ['jwt.denylist.store', ['redis'], Denylist::class],
    'kid not a string' => ['jwt.kid', 7, KeyRepository::class],
    'key path not a string' => ['jwt.public_key_path', ['a.pem'], KeyRepository::class],
    'issuer not a string' => ['jwt.issuer', ['iss'], UserTokenIssuer::class],
    'service name not a string' => ['jwt.service.name', ['svc'], NativeServiceTokenService::class],
    'service secret not a string' => ['jwt.service.secret', 123, NativeServiceTokenService::class],
]);
