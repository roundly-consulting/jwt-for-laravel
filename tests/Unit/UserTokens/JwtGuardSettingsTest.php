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

    return Jwt::guard('x')->settings();
}

it('honours a per-guard option', function (string $key, mixed $value, string $property, mixed $expected): void {
    expect(settingsFor([$key => $value])->{$property})->toBe($expected);
})->with([
    'audience' => ['audience', 'clients', 'audience', 'clients'],
    'scope' => ['scope', 'custom', 'scope', 'custom'],
    'scope (enum case)' => ['scope', Scope::TwoFaPending, 'scope', '2fa_pending'],
    'check_denylist' => ['check_denylist', false, 'checkDenylist', false],
    'check_denylist (env string)' => ['check_denylist', 'false', 'checkDenylist', false],
    'check_denylist (env "off")' => ['check_denylist', 'off', 'checkDenylist', false],
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

it('defers to the global option when the per-guard value is unset or blank', function (string $key, mixed $value, string $property, mixed $expected): void {
    expect(settingsFor([$key => $value])->{$property})->toBe($expected);
})->with([
    'blank audience' => ['audience', '  ', 'audience', 'web'],
    'null audience' => ['audience', null, 'audience', 'web'],
    'null scope' => ['scope', null, 'scope', 'access'],
    'blank scope' => ['scope', ' ', 'scope', 'access'],
    'null identity' => ['identity', null, 'identity', TokenUser::class],
    'blank identity' => ['identity', '', 'identity', TokenUser::class],
    'blank check_denylist' => ['check_denylist', '', 'checkDenylist', true],
    'blank token_version' => ['token_version', '', 'tokenVersion', null],
]);

it('refuses an unusable per-guard value instead of deferring to the global one (strict config)', function (string $key, mixed $value): void {
    expect(fn () => settingsFor([$key => $value]))
        ->toThrow(JwtMisconfigured::class, "Configuration value [auth.guards.x.{$key}]");
})->with([
    'non-string audience' => ['audience', ['web']],
    'non-string scope' => ['scope', 42],
    'check_denylist typo' => ['check_denylist', 'disabled'],
    'identity not a ClaimsAuthenticatable' => ['identity', stdClass::class],
    'identity not a class' => ['identity', 'Not\\A\\Class'],
]);

it('refuses an unusable global scope or audience (strict config)', function (string $key, mixed $value): void {
    config([$key => $value]);

    expect(fn () => settingsFor([]))->toThrow(JwtMisconfigured::class, "Configuration value [{$key}]");
})->with([
    'scope' => ['jwt.guard.scope', false],
    'audience' => ['jwt.audience', 42],
]);

it('reads an unset or blank global scope as access (strict config)', function (mixed $unset): void {
    config(['jwt.guard.scope' => $unset]);

    expect(settingsFor([])->scope)->toBe('access');
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('refuses a typo in a per-guard check_denylist instead of deferring to the global one (strict config)', function (mixed $junk): void {
    expect(fn () => settingsFor(['check_denylist' => $junk]))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [auth.guards.x.check_denylist] must be a boolean');
})->with(['maybe', 'disabled', [['on']]]);

it('refuses a typo in the global check_denylist (strict config)', function (): void {
    config(['jwt.guard.check_denylist' => 'disabled']);

    expect(fn () => settingsFor([]))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [jwt.guard.check_denylist] must be a boolean (true/false, 1/0, on/off or yes/no), [disabled] given.');
});

it('reads an unset or blank check_denylist as the shipped default, on (strict config)', function (mixed $unset): void {
    // A blank JWT_CHECK_DENYLIST= is not set: it must never read as `false` and switch revocation off.
    config(['jwt.guard.check_denylist' => $unset]);

    expect(settingsFor([])->checkDenylist)->toBeTrue()
        ->and(settingsFor(['check_denylist' => $unset])->checkDenylist)->toBeTrue();
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('normalises a global Scope case to its wire value', function (): void {
    config(['jwt.guard.scope' => Scope::EmailVerify]);

    expect(settingsFor([])->scope)->toBe('email_verify');
});

it('keeps a configured token_version closure as-is', function (): void {
    $resolver = fn (): int => 3;

    expect(settingsFor(['token_version' => $resolver])->tokenVersion)->toBe($resolver);
});

it('refuses a global identity that is not a ClaimsAuthenticatable instead of using TokenUser (strict config)', function (): void {
    config(['jwt.guard.identity' => 'Not\\A\\Class']);

    expect(fn () => settingsFor([]))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [jwt.guard.identity] must be a class implementing');
});

it('uses TokenUser when no identity is configured at all', function (): void {
    config(['jwt.guard.identity' => null]);

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
        ->and($users->audience())->toBe(Jwt::guard('users')->settings()->audience)->toBe('web')
        ->and($clients->audience())->toBe(Jwt::guard('clients')->settings()->audience)->toBe('clients');
});

it('refuses a guard that is not a jwt guard', function (array $guards, string $name): void {
    config(['auth.guards' => $guards]);

    Jwt::guard($name)->settings();
})->with([
    'session guard' => [['web' => ['driver' => 'session', 'provider' => 'users']], 'web'],
    'unknown guard' => [[], 'missing'],
])->throws(JwtMisconfigured::class, 'is not configured with the jwt driver');
