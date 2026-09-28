<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\GuardTokens;
use RoundlyConsulting\Jwt\UserTokens\JwtGuardSettings;
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
        'jwt.service.issuer' => 'billing',
        'app.service' => 'web',
        'auth.guards.users' => ['driver' => 'jwt', 'audience' => 'app-users'],
        'auth.guards.clients' => ['driver' => 'jwt', 'audience' => 'app-clients', 'scope' => 'partner'],
        'auth.guards.internal' => ['driver' => 'service-jwt'],
        'auth.guards.web' => ['driver' => 'session', 'provider' => 'users'],
    ]);
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

// jwt has no src/Actions — it is a stateless token codec plus a cache-backed
// denylist, which the convention lets expose service objects (issuer, verifier,
// denylist contracts) instead of actions — so toReachEveryAction() does not apply.
it('pins the facade contract', function (): void {
    expect(Jwt::class)
        ->toDocumentItsRoot()
        ->toBeFakeable();
});

it('scopes mint, verify, settings and audience to one guard', function (): void {
    $guard = Jwt::guard('clients');
    $issued = $guard->mint('client-1', Scope::Access, 120, ['org' => 7]);
    $claims = $guard->verify($issued->token);

    expect($guard)->toBeInstanceOf(GuardTokens::class)
        ->and($guard->audience())->toBe('app-clients')
        ->and($guard->settings())->toBeInstanceOf(JwtGuardSettings::class)
        ->and($guard->settings()->scope)->toBe('partner')
        ->and($claims->string('aud'))->toBe('app-clients')
        ->and($claims->int('org'))->toBe(7);
});

it('mints an access token for the guard audience', function (): void {
    $issued = Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-1')->email('a@b.test'));

    expect(Jwt::guard('users')->verify($issued->token)->string('email'))->toBe('a@b.test')
        ->and(Jwt::verify($issued->token, 'app-users')->string('aud'))->toBe('app-users');
});

it('accepts a request already addressed to the guard audience', function (): void {
    $issued = Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-1')->audience('app-users'));

    expect(Jwt::guard('users')->verify($issued->token)->string('sub'))->toBe('user-1');
});

it('refuses a request addressed to another audience', function (): void {
    Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-1')->audience('app-clients'));
})->throws(JwtMisconfigured::class, 'names audience [app-clients], but jwt guard [users] mints for [app-users]');

it('refuses a token minted for another guard', function (): void {
    $usersToken = Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-1'))->token;

    expect(fn () => Jwt::guard('clients')->verify($usersToken))->toThrow(ClaimMismatch::class)
        ->and(fn () => Jwt::verify($usersToken))->toThrow(ClaimMismatch::class);
});

it('never answers with another guard\'s claims', function (): void {
    Route::middleware('auth:users')->get('/me', fn () => response()->json([
        'users' => Jwt::guard('users')->claims()?->string('sub'),
        'clients' => Jwt::guard('clients')->claims()?->string('sub'),
    ]));

    $token = Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-5'))->token;

    $this->withToken($token)->getJson('/me')->assertOk()->assertExactJson(['users' => 'user-5', 'clients' => null]);
});

it('refuses a guard that is not a jwt guard', function (string $name): void {
    Jwt::guard($name);
})->with(['web', 'internal', 'missing'])->throws(JwtMisconfigured::class, 'is not configured with the jwt driver');

it('issues, verifies and attaches service tokens through services()', function (): void {
    Http::fake();
    config(['app.service' => 'ledger']);

    $services = Jwt::services();
    $issued = $services->issue('ledger', ['job' => 'sync']);

    expect($services)->toBeInstanceOf(Services::class)
        ->and($services->verify($issued->token)->string('job'))->toBe('sync')
        ->and($services->request('ledger'))->toBeInstanceOf(PendingRequest::class);

    $services->authenticate(Http::baseUrl('https://ledger.test'), 'ledger')->get('/ping');

    Http::assertSent(fn ($request): bool => str_starts_with((string) $request->header('Authorization')[0], 'Bearer '));
});

it('reads the calling service claims from the service-jwt guard', function (): void {
    config(['app.service' => 'web', 'jwt.service.issuer' => 'billing']);

    Route::middleware('auth:internal')->get('/internal', fn () => response()->json([
        'any' => Jwt::services()->claims()?->string('iss'),
        'named' => Jwt::services()->claims('internal')?->string('iss'),
        'not-a-service-guard' => Jwt::services()->claims('users')?->string('iss'),
    ]));

    expect(Jwt::services()->claims())->toBeNull();

    $token = Jwt::services()->issue('web')->token;

    $this->withToken($token)->getJson('/internal')->assertOk()->assertExactJson([
        'any' => 'billing',
        'named' => 'billing',
        'not-a-service-guard' => null,
    ]);
});

it('returns no service claims when no service guard has a caller', function (): void {
    expect(Jwt::services()->claims('internal'))->toBeNull()
        ->and(Jwt::services()->claims('missing'))->toBeNull();
});

it('exports the public key and its JWK set', function (): void {
    config(['jwt.kid' => 'key-2026']);
    app()->forgetInstance(KeyRepository::class);

    $jwks = Jwt::jwks();
    $key = $jwks['keys'][0];
    $public = Jwt::publicKey();

    expect($public)->toBeInstanceOf(RsaKey::class)
        ->and($public->publicPem())->toBe(RsaKey::public(publicKeyPem())->publicPem())
        ->and(array_keys($jwks))->toBe(['keys'])
        ->and($jwks['keys'])->toHaveCount(1)
        ->and($key['kty'])->toBe('RSA')
        ->and($key['alg'])->toBe('RS256')
        ->and($key['use'])->toBe('sig')
        ->and($key['kid'])->toBe('key-2026')
        ->and(Base64Url::decode($key['n']))->toBe($public->modulus())
        ->and(Base64Url::decode($key['e']))->toBe($public->exponent());
});

it('publishes no kid when none is configured', function (): void {
    expect(Jwt::jwks()['keys'][0])->not->toHaveKey('kid');
});

it('refuses to export a key that is not configured', function (): void {
    config(['jwt.public_key_path' => null]);
    app()->forgetInstance(KeyRepository::class);

    Jwt::jwks();
})->throws(KeyLoadFailed::class, 'JWT_PUBLIC_KEY_PATH');

it('serves the same API through the injected manager', function (): void {
    $manager = app(JwtManager::class);
    $issued = $manager->guard('users')->mintAccessToken(AccessTokenRequest::for('user-1'));

    expect($manager)->toBe(Jwt::getFacadeRoot())
        ->and($manager->guard('users')->verify($issued->token)->string('sub'))->toBe('user-1')
        ->and($manager->services()->verify($manager->services()->issue('web')->token)->string('aud'))->toBe('web')
        ->and($manager->jwks())->toBe(Jwt::jwks());
});
