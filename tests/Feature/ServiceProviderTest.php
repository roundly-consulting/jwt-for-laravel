<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
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
        public function verify(string $jwt, ?string $audience = null): Claims
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

it('registers the key-generation command', function (): void {
    expect(array_keys(Artisan::all()))->toContain('jwt:generate-keys');
});

it('reports the token setup in about, without leaking key material', function (): void {
    config([
        'jwt.private_key_path' => '/secret/place/jwt-private.pem',
        'jwt.public_key_path' => '/secret/place/jwt-public.pem',
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.ttl' => 900,
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.service.secrets' => null,
        'jwt.guard.check_denylist' => true,
        'jwt.authorize_from_claims' => true,
    ]);

    // The section reports presence, never the path, the key, or the secret.
    // `mustRender` is the positive proof the capture is real: a negative-only
    // leak check passes just as happily against empty output.
    expect('jwt')->toLeakNoSecrets(
        secrets: [
            '/secret/place/jwt-private.pem',
            '/secret/place/jwt-public.pem',
            '/secret/place',
            'unit-test-service-secret-0123456789ab',
        ],
        mustRender: ['RS256', 'HS256 (shared secret)', '900s', 'SET'],
    );
});

it('flags a missing key, issuer, audience and service secret in about', function (): void {
    config([
        'jwt.private_key_path' => null,
        'jwt.public_key_path' => '',
        'jwt.issuer' => null,
        'jwt.audience' => null,
        'jwt.ttl' => 'nonsense',
        'jwt.service.secret' => null,
        'jwt.service.secrets' => null,
        'jwt.guard.check_denylist' => false,
        'jwt.authorize_from_claims' => false,
    ]);

    Artisan::call('about --only=jwt');
    $output = Artisan::output();

    expect($output)->toContain('MISSING')
        ->and($output)->toContain('HS256 (no secret)')
        ->and($output)->toContain('DEFAULT')
        ->and($output)->toContain('OFF');
});

it('prefers per-issuer secrets over the shared secret in about', function (): void {
    config([
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.service.secrets' => 'logger:per-issuer-secret-for-logger-0123456789',
    ]);

    Artisan::call('about --only=jwt');

    expect(Artisan::output())->toContain('HS256 (per-issuer secrets)');
});

/*
 * The service's own name — what inbound service tokens must carry as `aud`, and the
 * default `iss` of the tokens it mints. A stock Laravel app has no `app.service`
 * key, so reading only that left audience pinning misconfigured out of the box. The
 * package owns `jwt.service.name`; a host's `app.service` still wins over the
 * app-name fallback, so services that define it keep their identity unchanged.
 */
function serviceTokenFor(string $audience): string
{
    return app(NativeServiceTokenService::class)->issue($audience)->token;
}

it('names the service after the app when neither jwt.service.name nor app.service is set', function (): void {
    config(['app.name' => 'Billing API', 'app.service' => null, 'jwt.service.issuer' => 'caller', 'jwt.service.secret' => 'unit-test-service-secret-0123456789ab']);

    $service = app(NativeServiceTokenService::class);

    expect($service->verify(serviceTokenFor('billing-api'))->string('aud'))->toBe('billing-api')
        ->and(fn () => $service->verify(serviceTokenFor('Billing API')))->toThrow(ClaimMismatch::class);
});

it('prefers jwt.service.name, then app.service, then the app name', function (array $config, string $expected): void {
    config(['app.name' => 'Billing API', 'jwt.service.issuer' => 'caller', 'jwt.service.secret' => 'unit-test-service-secret-0123456789ab', ...$config]);

    expect(app(NativeServiceTokenService::class)->verify(serviceTokenFor($expected))->string('aud'))->toBe($expected);
})->with([
    'jwt.service.name wins' => [['jwt.service.name' => 'billing', 'app.service' => 'cosmos-billing'], 'billing'],
    'app.service next (a host-published config without the name key)' => [['jwt.service.name' => null, 'app.service' => 'cosmos-billing'], 'cosmos-billing'],
    'blank name falls through' => [['jwt.service.name' => '  ', 'app.service' => 'cosmos-billing'], 'cosmos-billing'],
]);

it('mints under the service name when no issuer is configured', function (): void {
    config([
        'app.name' => 'Billing API',
        'app.service' => null,
        'jwt.service.issuer' => null,
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
    ]);

    $issued = app(NativeServiceTokenService::class)->issue('billing-api');

    expect(app(NativeServiceTokenService::class)->verify($issued->token)->string('iss'))->toBe('billing-api');
});

it('still fails closed, naming the key to set, when no service name can be derived', function (): void {
    config(['app.name' => '', 'app.service' => null, 'jwt.service.name' => null, 'jwt.service.issuer' => 'caller', 'jwt.service.secret' => 'unit-test-service-secret-0123456789ab']);

    app(NativeServiceTokenService::class)->verify(serviceTokenFor('anything'));
})->throws(ServiceAuthMisconfigured::class, 'JWT_SERVICE_NAME');
