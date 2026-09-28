<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\Scope;

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
    ]);

    Route::middleware('auth:api')->get('/whoami', fn () => response()->json([
        'sub' => Jwt::guard('api')->claims()?->string('sub'),
    ]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('mints and verifies an access token round-trip through the facade', function (): void {
    $issued = Jwt::mintAccessToken(
        AccessTokenRequest::for('user-1')->email('a@b.test', verified: true)->permissions('posts.view'),
    );

    $claims = Jwt::verify($issued->token);

    expect($claims->string('sub'))->toBe('user-1')
        ->and($claims->string('scope'))->toBe(Scope::Access->value)
        ->and($claims->string('email'))->toBe('a@b.test');
});

it('mints challenge and email-verify tokens through the facade', function (): void {
    expect(Jwt::verify(Jwt::mintChallengeToken('user-1')->token)->string('scope'))->toBe(Scope::TwoFaPending->value)
        ->and(Jwt::verify(Jwt::mintEmailVerifyToken('user-1', 'a@b.test')->token)->string('scope'))->toBe(Scope::EmailVerify->value);
});

it('mints a generic token through the facade', function (): void {
    $issued = Jwt::mint('user-1', 'custom', 120, ['x' => 1]);

    expect(Jwt::verify($issued->token)->string('scope'))->toBe('custom');
});

it('accepts a Scope case through the facade, as the README shows', function (): void {
    $subject = 'user-1';

    $issued = Jwt::mint($subject, Scope::Access, ttl: 900);

    expect(Jwt::verify($issued->token)->string('scope'))->toBe('access');
});

it('mints the same claims for a Scope case and its string value', function (): void {
    $fromEnum = Jwt::verify(Jwt::mint('user-1', Scope::TwoFaPending, 120)->token)->all();
    $fromString = Jwt::verify(Jwt::mint('user-1', '2fa_pending', 120)->token)->all();

    unset($fromEnum['jti'], $fromString['jti']);

    expect($fromEnum)->toBe($fromString);
});

it('exposes the service-token accessor and the bound denylist', function (): void {
    $issued = Jwt::services()->issue('web');

    expect(Jwt::services())->toBeInstanceOf(Services::class)
        ->and(Jwt::services()->verify($issued->token)->string('aud'))->toBe('web')
        ->and(Jwt::denylist())->toBe(app(Denylist::class));
});

it('logs out a freshly issued token via the facade', function (): void {
    $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));

    expect(Jwt::denylist()->has($issued->jti))->toBeFalse();

    Jwt::logout($issued);

    expect(Jwt::denylist()->has($issued->jti))->toBeTrue();
});

it('denylists a token from its verified claims', function (): void {
    $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));
    $claims = Jwt::verify($issued->token);

    Jwt::denyClaims($claims);

    expect(Jwt::denylist()->has($issued->jti))->toBeTrue();
});

it('reads the current request claims, null before authentication', function (): void {
    expect(Jwt::guard('api')->claims())->toBeNull();

    $token = Jwt::mintAccessToken(AccessTokenRequest::for('user-9'))->token;

    $this->withToken($token)->getJson('/whoami')->assertOk()->assertJson(['sub' => 'user-9']);
});

it('routes facade calls through the container-bound contract even when overridden', function (): void {
    $fake = new class implements UserTokenVerifier
    {
        public function verify(string $jwt, ?string $audience = null): Claims
        {
            return new Claims(['sub' => 'spied']);
        }
    };

    app()->instance(UserTokenVerifier::class, $fake);

    expect(Jwt::verify('anything')->string('sub'))->toBe('spied');
});

it('rethrows verification failures', function (): void {
    $token = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'))->token;
    [$h, $p, $s] = explode('.', $token);

    $s = ($s[0] === 'A' ? 'B' : 'A').substr($s, 1);

    Jwt::verify($h.'.'.$p.'.'.$s);
})->throws(InvalidSignature::class);

it('rethrows malformed-token failures', function (): void {
    Jwt::verify('not.a.token');
})->throws(JwtException::class);

it('resolves a guard audience, falling back to the configured one', function (): void {
    config([
        'auth.guards.users' => ['driver' => 'jwt', 'audience' => 'vetapp-users'],
        'auth.guards.blank' => ['driver' => 'jwt', 'audience' => ''],
    ]);

    expect(Jwt::guard('users')->audience())->toBe('vetapp-users')
        ->and(Jwt::guard('api')->audience())->toBe('web')
        ->and(Jwt::guard('blank')->audience())->toBe('web');
});

it('refuses a guard that is not a jwt guard', function (): void {
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users']]);

    Jwt::guard('web');
})->throws(JwtMisconfigured::class);

it('exposes the resolved settings of a guard', function (): void {
    config(['auth.guards.clients' => ['driver' => 'jwt', 'audience' => 'vetapp-clients', 'scope' => 'partner']]);

    $settings = Jwt::guard('clients')->settings();

    expect($settings->guard)->toBe('clients')
        ->and($settings->audience)->toBe('vetapp-clients')
        ->and($settings->scope)->toBe('partner');
});

it('mints and verifies for an explicit audience through the facade', function (): void {
    $issued = Jwt::mint('user-1', 'access', 120, [], 'clients');

    expect(Jwt::verify($issued->token, 'clients')->string('aud'))->toBe('clients')
        ->and(fn () => Jwt::verify($issued->token))->toThrow(ClaimMismatch::class);
});

it('reads the claims of one named guard', function (): void {
    config(['auth.guards.clients' => ['driver' => 'jwt', 'audience' => 'vetapp-clients']]);

    Route::middleware('auth:clients')->get('/clients/whoami', fn () => response()->json([
        'clients' => Jwt::guard('clients')->claims()?->string('sub'),
        'api' => Jwt::guard('api')->claims()?->string('sub'),
    ]));

    $token = Jwt::guard('clients')->mintAccessToken(AccessTokenRequest::for('client-7'))->token;

    $this->withToken($token)->getJson('/clients/whoami')->assertOk()->assertExactJson([
        'clients' => 'client-7',
        'api' => null,
    ]);
});

it('reads no claims for a guard before authentication, and refuses an unknown guard', function (): void {
    expect(Jwt::guard('api')->claims())->toBeNull()
        ->and(fn () => Jwt::guard('missing'))->toThrow(JwtMisconfigured::class);
});
