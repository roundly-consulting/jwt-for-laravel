<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Tests\Fixtures\CustomIdentity;
use RoundlyConsulting\Jwt\Tests\Fixtures\TokenVersionResolver;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\JwtGuardSettings;
use RoundlyConsulting\Jwt\UserTokens\Scope;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

beforeEach(function (): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.denylist.store' => 'array',
        'jwt.guard.scope' => 'access',
        'jwt.guard.check_denylist' => true,
        'jwt.guard.identity' => TokenUser::class,
        'jwt.guard.token_version' => null,
    ]);
});

/**
 * @param  array<string, mixed>  $options
 */
function settingsFor(array $options): JwtGuardSettings
{
    config(['auth.guards.x' => ['driver' => 'jwt', ...$options]]);

    return Jwt::guardSettings('x');
}

it('honours a per-guard option', function (string $key, mixed $value, string $property, mixed $expected): void {
    expect(settingsFor([$key => $value])->{$property})->toBe($expected);
})->with([
    'audience' => ['audience', 'clients', 'audience', 'clients'],
    'scope' => ['scope', 'custom', 'scope', 'custom'],
    'scope (enum case)' => ['scope', Scope::TwoFaPending, 'scope', '2fa_pending'],
    'check_denylist' => ['check_denylist', false, 'checkDenylist', false],
    'check_denylist (env string)' => ['check_denylist', 'false', 'checkDenylist', false],
    'identity' => ['identity', CustomIdentity::class, 'identity', CustomIdentity::class],
    'token_version' => ['token_version', TokenVersionResolver::class, 'tokenVersion', TokenVersionResolver::class],
]);

it('falls back to the global jwt option when the guard omits it', function (string $global, mixed $value, string $property): void {
    config([$global => $value]);

    expect(settingsFor([])->{$property})->toBe($value);
})->with([
    'audience' => ['jwt.audience', 'global-aud', 'audience'],
    'scope' => ['jwt.guard.scope', 'global-scope', 'scope'],
    'check_denylist' => ['jwt.guard.check_denylist', false, 'checkDenylist'],
    'identity' => ['jwt.guard.identity', CustomIdentity::class, 'identity'],
    'token_version' => ['jwt.guard.token_version', TokenVersionResolver::class, 'tokenVersion'],
]);

it('falls back to the global option when the per-guard value is unusable', function (string $key, mixed $value, string $property, mixed $expected): void {
    expect(settingsFor([$key => $value])->{$property})->toBe($expected);
})->with([
    'blank audience' => ['audience', '  ', 'audience', 'web'],
    'null audience' => ['audience', null, 'audience', 'web'],
    'non-string scope' => ['scope', 42, 'scope', 'access'],
    'non-boolean check_denylist' => ['check_denylist', 'maybe', 'checkDenylist', true],
    'identity not a ClaimsAuthenticatable' => ['identity', stdClass::class, 'identity', TokenUser::class],
    'blank token_version' => ['token_version', '', 'tokenVersion', null],
]);

it('normalises a global Scope case to its wire value', function (): void {
    config(['jwt.guard.scope' => Scope::EmailVerify]);

    expect(settingsFor([])->scope)->toBe('email_verify');
});

it('keeps a configured token_version closure as-is', function (): void {
    $resolver = fn (): int => 3;

    expect(settingsFor(['token_version' => $resolver])->tokenVersion)->toBe($resolver);
});

it('falls back to TokenUser when neither identity is usable', function (): void {
    config(['jwt.guard.identity' => 'Not\\A\\Class']);

    expect(settingsFor([])->identity)->toBe(TokenUser::class);
});

it('names the guard it resolved', function (): void {
    expect(settingsFor([])->guard)->toBe('x');
});

it('builds the guard from the very same settings', function (): void {
    config([
        'auth.guards.users' => ['driver' => 'jwt'],
        'auth.guards.clients' => ['driver' => 'jwt', 'audience' => 'clients'],
    ]);

    $users = Auth::guard('users');
    $clients = Auth::guard('clients');

    expect($users)->toBeInstanceOf(JwtGuard::class)
        ->and($clients)->toBeInstanceOf(JwtGuard::class)
        ->and($users->audience())->toBe(Jwt::guardSettings('users')->audience)->toBe('web')
        ->and($clients->audience())->toBe(Jwt::guardSettings('clients')->audience)->toBe('clients');
});

it('refuses a guard that is not a jwt guard', function (array $guards, string $name): void {
    config(['auth.guards' => $guards]);

    Jwt::guardSettings($name);
})->with([
    'session guard' => [['web' => ['driver' => 'session', 'provider' => 'users']], 'web'],
    'unknown guard' => [[], 'missing'],
])->throws(JwtMisconfigured::class, 'is not configured with the jwt driver');
