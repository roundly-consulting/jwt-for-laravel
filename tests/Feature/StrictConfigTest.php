<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\JwtServiceProvider;

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
