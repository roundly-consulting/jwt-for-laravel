<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;

/**
 * @param  list<string>  $allowedIssuers
 */
function serviceService(
    ?string $secret = 'service-secret',
    string $issuer = 'cosmos-logger',
    ?string $defaultAudience = 'cosmos-auth',
    array $allowedIssuers = [],
    string $serviceName = 'cosmos-auth',
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
        ->and($claims->string('iss'))->toBe('cosmos-logger')
        ->and($claims->string('aud'))->toBe('cosmos-auth')
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_060);
});

it('honours an explicit audience over the default', function (): void {
    $issued = serviceService()->issue('cosmos-billing');

    $target = serviceService(serviceName: 'cosmos-billing');

    expect($target->verify($issued->token)->string('aud'))->toBe('cosmos-billing');
});

it('rejects a token addressed to another service', function (): void {
    $issued = serviceService()->issue('cosmos-auth');

    serviceService(serviceName: 'cosmos-billing')->verify($issued->token);
})->throws(ClaimMismatch::class, 'audience');

it('accepts any issuer when the allow-list is empty', function (): void {
    $issued = serviceService(issuer: 'some-random-service')->issue();

    expect(serviceService()->verify($issued->token)->string('iss'))->toBe('some-random-service');
});

it('enforces a non-empty issuer allow-list', function (): void {
    $issued = serviceService(issuer: 'intruder')->issue();

    serviceService(allowedIssuers: ['cosmos-logger', 'cosmos-geo'])->verify($issued->token);
})->throws(ClaimMismatch::class, 'allow-listed');

it('accepts an allow-listed issuer', function (): void {
    $issued = serviceService(issuer: 'cosmos-logger')->issue();

    expect(serviceService(allowedIssuers: ['cosmos-logger'])->verify($issued->token)->string('iss'))
        ->toBe('cosmos-logger');
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
        'iss' => 'cosmos-logger',
        'aud' => 'cosmos-auth',
        'scope' => 'access',
        'exp' => 1_700_000_060,
    ], new HmacSecret('service-secret'), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'scope');

it('rejects a service token with an empty issuer', function (): void {
    $token = (new Encoder)->encode([
        'iss' => '',
        'aud' => 'cosmos-auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], new HmacSecret('service-secret'), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'issuer is missing');
