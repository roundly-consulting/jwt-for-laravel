<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;

const SERVICE_SECRET = 'unit-test-service-secret-0123456789ab';

/**
 * @param  list<string>  $allowedIssuers
 * @param  array<string, string>  $secrets
 */
function serviceService(
    ?string $secret = SERVICE_SECRET,
    string $issuer = 'logger',
    ?string $defaultAudience = 'auth',
    array $allowedIssuers = [],
    string $serviceName = 'auth',
    array $secrets = [],
): NativeServiceTokenService {
    return new NativeServiceTokenService(
        new Encoder,
        new Decoder,
        $secret,
        $issuer,
        $defaultAudience,
        60,
        $allowedIssuers,
        $serviceName,
        0,
        null,
        $secrets,
    );
}

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('issues and verifies a service token', function (): void {
    $service = serviceService();
    $issued = $service->issue();

    $claims = $service->verify($issued->token);

    expect($claims->string('scope'))->toBe('service')
        ->and($claims->string('iss'))->toBe('logger')
        ->and($claims->string('aud'))->toBe('auth')
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_060);
});

it('honours an explicit audience over the default', function (): void {
    $issued = serviceService()->issue('billing');

    $target = serviceService(serviceName: 'billing');

    expect($target->verify($issued->token)->string('aud'))->toBe('billing');
});

it('rejects a token addressed to another service', function (): void {
    $issued = serviceService()->issue('auth');

    serviceService(serviceName: 'billing')->verify($issued->token);
})->throws(ClaimMismatch::class, 'audience');

it('accepts any issuer when the allow-list is empty', function (): void {
    $issued = serviceService(issuer: 'some-random-service')->issue();

    expect(serviceService()->verify($issued->token)->string('iss'))->toBe('some-random-service');
});

it('enforces a non-empty issuer allow-list', function (): void {
    $issued = serviceService(issuer: 'intruder')->issue();

    serviceService(allowedIssuers: ['logger', 'geo'])->verify($issued->token);
})->throws(ClaimMismatch::class, 'allow-listed');

it('accepts an allow-listed issuer', function (): void {
    $issued = serviceService(issuer: 'logger')->issue();

    expect(serviceService(allowedIssuers: ['logger'])->verify($issued->token)->string('iss'))
        ->toBe('logger');
});

it('raises a misconfiguration when issuing without a secret', function (): void {
    serviceService(secret: null)->issue();
})->throws(ServiceAuthMisconfigured::class);

it('raises a misconfiguration when verifying without a secret', function (): void {
    serviceService(secret: '')->verify('a.b.c');
})->throws(ServiceAuthMisconfigured::class);

it('rejects a token that is not scoped to service', function (): void {
    // Mint an HS256 token with the same secret but a different scope.
    $encoder = new Encoder;
    $token = $encoder->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'access',
        'exp' => 1_700_000_060,
    ], new HmacSecret(SERVICE_SECRET), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'scope');

it('rejects a service token with an empty issuer', function (): void {
    $token = (new Encoder)->encode([
        'iss' => '',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], new HmacSecret(SERVICE_SECRET), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'issuer is missing');

it('raises a misconfiguration for a too-short shared secret, never a 401', function (): void {
    serviceService(secret: 'short')->issue();
})->throws(ServiceAuthMisconfigured::class, 'at least 32 random bytes');

it('raises a misconfiguration when issuing without any audience', function (): void {
    serviceService(defaultAudience: null)->issue();
})->throws(ServiceAuthMisconfigured::class, 'audience');

it('raises a misconfiguration when issuing with an empty issuer', function (): void {
    serviceService(issuer: '')->issue();
})->throws(ServiceAuthMisconfigured::class, 'JWT_SERVICE_ISSUER');

it('raises a misconfiguration when verifying with no service name', function (): void {
    serviceService(serviceName: '')->verify('a.b.c');
})->throws(ServiceAuthMisconfigured::class, 'app.service');

const ISSUER_SECRETS = [
    'logger' => 'per-issuer-secret-for-logger-0123456789',
    'geo' => 'per-issuer-secret-for-geo-0123456789abc',
];

it('issues and verifies with per-issuer secrets', function (): void {
    $issued = serviceService(issuer: 'logger', secrets: ISSUER_SECRETS)->issue();

    $claims = serviceService(secrets: ISSUER_SECRETS)->verify($issued->token);

    expect($claims->string('iss'))->toBe('logger');
});

it('rejects a token whose iss claims another issuer secret', function (): void {
    // Signed with geo's secret but claiming to be logger: the iss selects
    // logger's secret, whose signature cannot match.
    $token = (new Encoder)->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], new HmacSecret(ISSUER_SECRETS['geo']), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

it('rejects an unknown issuer as an invalid signature, not an enumeration oracle', function (): void {
    // An unknown `iss` burns a full HMAC verification against a fixed dummy
    // secret and fails as InvalidSignature — identical to a known issuer with a
    // bad signature — so the configured issuer set can't be probed.
    $token = (new Encoder)->encode([
        'iss' => 'intruder',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], new HmacSecret(SERVICE_SECRET), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

it('ignores the shared secret when per-issuer secrets are configured', function (): void {
    // Signed with the shared secret while per-issuer mode is active — must fail.
    $token = (new Encoder)->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], new HmacSecret(SERVICE_SECRET), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

it('raises a misconfiguration when the own issuer is absent from the secret map', function (): void {
    serviceService(issuer: 'unmapped', secrets: ISSUER_SECRETS)->issue();
})->throws(ServiceAuthMisconfigured::class, 'own issuer');

it('rejects an oversized bearer string before decoding', function (): void {
    $oversized = str_repeat('a', 9000).'.b.c';

    serviceService()->verify($oversized);
})->throws(MalformedToken::class, 'maximum permitted length');
