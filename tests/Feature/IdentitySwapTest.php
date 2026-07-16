<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Tests\Fixtures\CustomIdentity;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'jwt.guard.identity' => CustomIdentity::class,
        'auth.guards.api' => ['driver' => 'jwt'],
    ]);

    Route::middleware('auth:api')->get('/whoami', fn () => response()->json([
        'class' => auth()->user()::class,
        'tenant' => auth()->user()->tenant(),
    ]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('builds the configured identity class, not the packaged one', function (): void {
    $identity = CustomIdentity::fromClaims(new Claims(['sub' => 'user-1', 'tenant' => 'acme']));

    // `instanceof` is not enough: a TokenUser passes it and loses every host behaviour.
    expect($identity::class)->toBe(CustomIdentity::class)
        ->and($identity->tenant())->toBe('acme');
});

it('authenticates through the swapped identity', function (): void {
    $token = app(UserTokenIssuer::class)->mint('user-1', 'access', 900, ['tenant' => 'acme'])->token;

    $this->withToken($token)->getJson('/whoami')
        ->assertOk()
        ->assertJson(['class' => CustomIdentity::class, 'tenant' => 'acme']);
});
