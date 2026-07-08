<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
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
    expect(config('jwt.algo'))->toBe('RS256')
        ->and(config('jwt.service.scope'))->toBe('service')
        ->and(config('jwt.guard.scope'))->toBe('access');
});

it('binds the token contracts to their native implementations', function (): void {
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
    config(['auth.guards.api' => ['driver' => 'jwt']]);

    expect(Auth::guard('api'))->toBeInstanceOf(JwtGuard::class);
});

it('resolves the service-jwt guard driver', function (): void {
    config(['auth.guards.service' => ['driver' => 'service-jwt']]);

    expect(Auth::guard('service'))->toBeInstanceOf(ServiceGuard::class);
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
