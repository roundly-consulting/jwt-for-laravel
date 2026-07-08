<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Jwt\Events\ServiceTokenIssued;
use RoundlyConsulting\Jwt\Events\TokenDenied;
use RoundlyConsulting\Jwt\Events\TokenVerificationFailed;
use RoundlyConsulting\Jwt\Events\UserTokenIssued;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Scopes;

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'cosmos-web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'jwt.service.secret' => 'a-very-secret-service-key',
        'jwt.service.issuer' => 'cosmos-web',
        'app.service' => 'cosmos-web',
    ]);
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('dispatches UserTokenIssued when a user token is minted', function (): void {
    Event::fake();

    $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));

    Event::assertDispatched(UserTokenIssued::class, fn (UserTokenIssued $e): bool => $e->subject === 'user-1'
        && $e->scope === Scopes::ACCESS
        && $e->jti === $issued->jti
        && $e->expiresAt->equalTo($issued->expiresAt));
});

it('dispatches ServiceTokenIssued when a service token is issued', function (): void {
    Event::fake();

    $issued = app(ServiceTokenIssuer::class)->issue('cosmos-billing');

    Event::assertDispatched(ServiceTokenIssued::class, fn (ServiceTokenIssued $e): bool => $e->issuer === 'cosmos-web'
        && $e->audience === 'cosmos-billing'
        && $e->jti === $issued->jti);
});

it('dispatches TokenDenied when a token is denylisted', function (): void {
    Event::fake();

    $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));
    Jwt::logout($issued);

    Event::assertDispatched(TokenDenied::class, fn (TokenDenied $e): bool => $e->jti === $issued->jti
        && $e->until->equalTo($issued->expiresAt));
});

it('does not dispatch TokenDenied for an already-expired token', function (): void {
    Event::fake();

    Jwt::denylist()->deny('old-jti', CarbonImmutable::now()->subSecond());

    Event::assertNotDispatched(TokenDenied::class);
});

it('dispatches TokenVerificationFailed on explicit verify failure with no sensitive data', function (): void {
    Event::fake();

    try {
        Jwt::verify('not.a.token');
    } catch (Throwable) {
        // expected
    }

    Event::assertDispatched(TokenVerificationFailed::class, function (TokenVerificationFailed $e): bool {
        expect($e->reason)->not->toContain('not.a.token')
            ->and($e->exceptionClass)->toStartWith('RoundlyConsulting\Jwt\Jose\Exceptions\\');

        return true;
    });
});

it('does not emit an event when the guard silently fails to resolve a request', function (): void {
    Event::fake();

    // The guard uses the verifier contract directly (not the manager), so an
    // anonymous/bad-token probe must not raise TokenVerificationFailed.
    config(['auth.guards.api' => ['driver' => 'jwt']]);

    Route::middleware('auth:api')->get('/probe', fn () => 'ok');

    $this->withToken('bogus')->getJson('/probe')->assertUnauthorized();

    Event::assertNotDispatched(TokenVerificationFailed::class);
});
