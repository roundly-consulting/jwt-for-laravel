<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\Testing\JwtFake;
use RoundlyConsulting\Jwt\Testing\RecordedToken;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Scope;

beforeEach(function (): void {
    // Deliberately no key paths, issuer, audience or service secret: the fake
    // supplies in-memory keys and test values.
    config([
        'jwt.private_key_path' => null,
        'jwt.public_key_path' => null,
        'jwt.issuer' => null,
        'jwt.audience' => null,
        'jwt.service.secret' => null,
        'jwt.denylist.store' => 'array',
        'app.service' => 'web',
        'auth.guards.api' => ['driver' => 'jwt'],
        'auth.guards.clients' => ['driver' => 'jwt', 'audience' => 'app-clients'],
    ]);
});

it('installs a manager subtype over in-memory keys', function (): void {
    $fake = Jwt::fake();
    $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));

    expect($fake)->toBeInstanceOf(JwtManager::class)
        ->and(app(JwtManager::class))->toBe($fake)
        ->and(Jwt::verify($issued->token)->string('sub'))->toBe('user-1')
        ->and(Jwt::verify($issued->token)->string('iss'))->toBe('jwt-fake-issuer')
        ->and(Jwt::jwks()['keys'][0]['kty'])->toBe('RSA')
        ->and(config('jwt.audience'))->toBe('jwt-fake-audience');
});

it('keeps a configured issuer, audience and kid', function (): void {
    config(['jwt.issuer' => 'real-issuer', 'jwt.audience' => 'real-aud', 'jwt.kid' => 'k1']);

    Jwt::fake();

    $claims = Jwt::verify(Jwt::mint('user-1', Scope::Access, 60)->token);

    expect($claims->string('iss'))->toBe('real-issuer')
        ->and($claims->string('aud'))->toBe('real-aud')
        ->and(Jwt::jwks()['keys'][0]['kid'])->toBe('k1');
});

it('asserts minted user tokens, by claims', function (): void {
    $fake = Jwt::fake();

    $fake->assertNothingMinted();
    expect(fn () => $fake->assertMinted())->toThrow(ExpectationFailedException::class);

    Jwt::mintAccessToken(AccessTokenRequest::for('user-1')->permissions('posts.view'));

    $fake->assertMinted();
    $fake->assertMinted(fn (Claims $claims): bool => $claims->string('sub') === 'user-1' && $claims->list('permissions') === ['posts.view']);

    expect(fn () => $fake->assertMinted(fn (Claims $claims): bool => $claims->string('sub') === 'user-2'))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingMinted())->toThrow(ExpectationFailedException::class, '1 were');
});

it('records every mint verb, the guard handle and the injected manager', function (): void {
    $fake = Jwt::fake();

    Jwt::mint('u', 'custom', 60);
    Jwt::mintChallengeToken('u');
    Jwt::mintEmailVerifyToken('u', 'u@example.test');
    Jwt::guard('clients')->mintAccessToken(AccessTokenRequest::for('c'));
    Jwt::guard('clients')->mint('c', Scope::Access, 60);
    app(JwtManager::class)->mintAccessToken(AccessTokenRequest::for('di'));

    expect(array_map(fn (RecordedToken $t): string => $t->claims->string('scope'), $fake->minted()))
        ->toBe(['custom', '2fa_pending', 'email_verify', 'access', 'access', 'access']);

    $fake->assertMinted(fn (Claims $claims): bool => $claims->get('aud') === 'app-clients');
    $fake->assertMinted(fn (Claims $claims): bool => $claims->get('sub') === 'di');
});

it('records an already-expired token like any other', function (): void {
    $fake = Jwt::fake();

    Jwt::mint('u', Scope::Access, -60);

    $fake->assertMinted(fn (Claims $claims): bool => $claims->int('exp') < CarbonImmutable::now()->getTimestamp());
});

it('asserts service tokens issued through services()', function (): void {
    Http::fake();
    $fake = Jwt::fake();

    $fake->assertNothingIssuedToServices();
    expect(fn () => $fake->assertServiceTokenIssued())->toThrow(ExpectationFailedException::class);

    Jwt::services()->issue('web', ['job' => 'sync']);
    Jwt::services()->request('billing')->get('https://billing.test/ping');
    Jwt::services()->authenticate(Http::baseUrl('https://ledger.test'), 'ledger')->get('/ping');

    $fake->assertServiceTokenIssued();
    $fake->assertServiceTokenIssued('billing');
    $fake->assertServiceTokenIssued('web', fn (Claims $claims): bool => $claims->get('job') === 'sync');

    expect($fake->serviceTokens())->toHaveCount(3)
        ->and(Jwt::services()->verify($fake->serviceTokens()[0]->token->token)->string('aud'))->toBe('web')
        ->and(fn () => $fake->assertServiceTokenIssued('mail'))->toThrow(ExpectationFailedException::class, 'for [mail]')
        ->and(fn () => $fake->assertServiceTokenIssued('web', fn (Claims $claims): bool => false))->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingIssuedToServices())->toThrow(ExpectationFailedException::class, '3 were');
});

it('asserts denies made through the denylist, logout and denyClaims', function (): void {
    $fake = Jwt::fake();

    $fake->assertNothingDenied();
    expect(fn () => $fake->assertDenied())->toThrow(ExpectationFailedException::class);

    $a = Jwt::mintAccessToken(AccessTokenRequest::for('a'));
    $b = Jwt::mintAccessToken(AccessTokenRequest::for('b'));
    $c = Jwt::mintAccessToken(AccessTokenRequest::for('c'));

    Jwt::logout($a);
    Jwt::denyClaims(Jwt::verify($b->token));
    Jwt::denylist()->deny('manual-jti', CarbonImmutable::now()->addMinute());

    $fake->assertDenied();
    $fake->assertDenied($a->jti);
    $fake->assertDenied($b->jti);
    $fake->assertDenied('manual-jti');

    expect(Jwt::denylist()->has($a->jti))->toBeTrue()
        ->and(Jwt::denylist()->has($c->jti))->toBeFalse()
        ->and($fake->denied())->toBe([$a->jti, $b->jti, 'manual-jti'])
        ->and(fn () => $fake->assertDenied($c->jti))->toThrow(ExpectationFailedException::class, "token [{$c->jti}]")
        ->and(fn () => $fake->assertNothingDenied())->toThrow(ExpectationFailedException::class, '3 token(s)');
});

it('authenticates a guard with actingAs', function (): void {
    $fake = Jwt::fake();

    Route::middleware('auth:api')->get('/me', fn () => response()->json([
        'sub' => Jwt::guard('api')->claims()?->string('sub'),
        'org' => Jwt::guard('api')->claims()?->get('org'),
    ]));

    $issued = $fake->actingAs(['sub' => 'user-7', 'org' => 42, 'aud' => 'ignored'], 'api');

    $this->getJson('/me')->assertOk()->assertExactJson(['sub' => 'user-7', 'org' => 42]);
    $this->getJson('/me')->assertOk();

    expect(Jwt::guard('api')->claims()?->string('sub'))->toBe('user-7')
        ->and(Jwt::verify($issued->token)->string('aud'))->toBe('jwt-fake-audience')
        ->and(auth()->getDefaultDriver())->toBe('api');

    $fake->assertNothingMinted();
});

it('acts on a guard with its own audience, from a Claims object, and replaces an earlier actingAs', function (): void {
    $fake = Jwt::fake();

    Route::middleware('auth:clients')->get('/client', fn () => response()->json(['sub' => Jwt::guard('clients')->claims()?->string('sub')]));

    $fake->actingAs(['sub' => 'user-1'], 'api');
    $fake->actingAs(new Claims(['sub' => 'client-9']), 'clients');

    $this->getJson('/client')->assertOk()->assertExactJson(['sub' => 'client-9']);
});

it('lets an explicit bearer win over actingAs', function (): void {
    $fake = Jwt::fake();

    Route::middleware('auth:api')->get('/me', fn () => response()->json(['sub' => Jwt::guard('api')->claims()?->string('sub')]));

    $fake->actingAs(['sub' => 'user-1'], 'api');
    $other = Jwt::mintAccessToken(AccessTokenRequest::for('user-2'))->token;

    $this->withToken($other)->getJson('/me')->assertOk()->assertExactJson(['sub' => 'user-2']);
});

it('refuses actingAs without a subject or on a non-jwt guard', function (): void {
    $fake = Jwt::fake();

    expect(fn () => $fake->actingAs(['org' => 1], 'api'))->toThrow(InvalidArgumentException::class, '"sub"')
        ->and(fn () => $fake->actingAs(['sub' => 1], 'missing'))->toThrow(JwtMisconfigured::class);
});

it('honours a scope passed to actingAs', function (): void {
    $fake = Jwt::fake();

    $issued = $fake->actingAs(['sub' => 5, 'scope' => '2fa_pending'], 'api');

    expect(Jwt::verify($issued->token)->string('scope'))->toBe('2fa_pending')
        ->and(Jwt::verify($issued->token)->string('sub'))->toBe('5')
        ->and(Jwt::guard('api')->claims())->toBeNull();
});

it('is a JwtFake', function (): void {
    expect(Jwt::fake())->toBeInstanceOf(JwtFake::class);
});
