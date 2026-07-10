<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenVerifier;

it('merges the package config', function (): void {
    expect(config('jwt.guard.scope'))->toBe('access')
        ->and(config('jwt.ttl'))->toBe(900)
        ->and(config('jwt.denylist.prefix'))->toBe('jwt:denylist:');
});

it('binds the token contracts to their native implementations', function (): void {
    config(['jwt.issuer' => 'jwt-issuer', 'jwt.audience' => 'web']);

    expect(app(UserTokenIssuer::class))->toBeInstanceOf(NativeUserTokenIssuer::class)
        ->and(app(UserTokenVerifier::class))->toBeInstanceOf(NativeUserTokenVerifier::class)
        ->and(app(ServiceTokenIssuer::class))->toBeInstanceOf(NativeServiceTokenService::class)
        ->and(app(ServiceTokenVerifier::class))->toBeInstanceOf(NativeServiceTokenService::class)
        ->and(app(Denylist::class))->toBeInstanceOf(CacheDenylist::class);
});

it('binds one service instance for both service-token contracts', function (): void {
    expect(app(ServiceTokenIssuer::class))->toBe(app(ServiceTokenVerifier::class));
});

it('resolves the jwt guard driver', function (): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'auth.guards.api' => ['driver' => 'jwt'],
    ]);

    expect(Auth::guard('api'))->toBeInstanceOf(JwtGuard::class);
});

it('refuses to resolve user-token services with an empty issuer or audience', function (): void {
    config(['jwt.issuer' => '', 'jwt.audience' => 'web']);

    expect(fn () => app(UserTokenVerifier::class))->toThrow(JwtMisconfigured::class);

    config(['jwt.issuer' => 'jwt-issuer', 'jwt.audience' => '']);

    expect(fn () => app(UserTokenIssuer::class))->toThrow(JwtMisconfigured::class);
});

it('resolves the service-jwt guard driver', function (): void {
    config(['auth.guards.service' => ['driver' => 'service-jwt']]);

    expect(Auth::guard('service'))->toBeInstanceOf(ServiceGuard::class);
});

it('parses the per-issuer secret map and round-trips a token through it', function (): void {
    config([
        'app.service' => 'auth',
        'jwt.service.issuer' => 'logger',
        'jwt.service.secrets' => 'logger:per-issuer-secret-for-logger-0123456789, geo:per-issuer-secret-for-geo-0123456789abc, malformed-pair',
    ]);

    $service = app(NativeServiceTokenService::class);
    $issued = $service->issue('auth');

    expect($service->verify($issued->token)->string('iss'))->toBe('logger');
});

it('trims padding around per-issuer secret pairs', function (): void {
    config([
        'app.service' => 'auth',
        'jwt.service.issuer' => 'logger',
        // Spaces around the colon and after the comma must not derive a
        // different HMAC key or a never-matching issuer.
        'jwt.service.secrets' => 'logger : per-issuer-secret-for-logger-0123456789 ,  geo:per-issuer-secret-for-geo-0123456789abc',
    ]);

    $service = app(NativeServiceTokenService::class);
    $issued = $service->issue('auth');

    expect($service->verify($issued->token)->string('iss'))->toBe('logger');
});

it('trims padding around issuer allow-list entries', function (): void {
    config([
        'app.service' => 'auth',
        'jwt.service.issuer' => 'logger',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        // A padded allow-list entry must still match a token's issuer.
        'jwt.service.issuers' => [' logger ', ' geo'],
    ]);

    $service = app(NativeServiceTokenService::class);
    $issued = $service->issue('auth');

    expect($service->verify($issued->token)->string('iss'))->toBe('logger');
});

it('lets the host override a bound contract', function (): void {
    $fake = new class implements UserTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            return new Claims([]);
        }
    };

    app()->instance(UserTokenVerifier::class, $fake);

    expect(app(UserTokenVerifier::class))->toBe($fake);
});

it('publishes the config under the jwt-config tag', function (): void {
    $groups = ServiceProvider::$publishGroups;

    expect($groups)->toHaveKey('jwt-config');
});
