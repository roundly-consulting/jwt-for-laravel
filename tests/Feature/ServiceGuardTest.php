<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'app.service' => 'auth',
        'jwt.service.secret' => 'shared-service-secret',
        'jwt.service.issuer' => 'logger',
        'jwt.service.audience' => 'auth',
        'jwt.leeway' => 0,
        // For minting the cross-family (user) token used in a negative test.
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'auth.guards.service' => ['driver' => 'service-jwt'],
    ]);

    Route::middleware('auth:service')->get('/internal', fn () => response()->json([
        'iss' => auth()->id(),
    ]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('authenticates a valid service token', function (): void {
    $token = app(ServiceTokenIssuer::class)->issue('auth')->token;

    $this->withToken($token)->getJson('/internal')
        ->assertOk()
        ->assertJson(['iss' => 'logger']);
});

it('rejects a request with no token', function (): void {
    $this->getJson('/internal')->assertUnauthorized();
});

it('rejects a user (RS256) token at the service guard', function (): void {
    $token = app(UserTokenIssuer::class)->mint('user-1', 'access', 900)->token;

    $this->withToken($token)->getJson('/internal')->assertUnauthorized();
});

it('surfaces a missing secret as a 500, not a 401', function (): void {
    config(['jwt.service.secret' => '']);

    $this->withToken('a.b.c')->getJson('/internal')->assertStatus(500);
});
