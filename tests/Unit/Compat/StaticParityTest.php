<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('agrees with each committed static token', function (string $file, array $meta): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp($meta['verify_now']));

    $token = trim(readFixture('tokens/'.$file));
    $decoder = new Decoder;

    $algorithm = $meta['alg'] === 'RS256' ? Algorithm::RS256 : Algorithm::HS256;
    $key = $meta['key'] === 'rsa'
        ? RsaKey::public(publicKeyPem())
        : manifestHmacSecret($meta['key']);

    if ($meta['outcome'] === 'expired') {
        expect(fn () => $decoder->decode($token, $key, $algorithm, 0))->toThrow(TokenExpired::class);

        return;
    }

    $claims = $decoder->decode($token, $key, $algorithm, 0);

    expect($claims->string('scope'))->toBe($meta['scope']);
})->with(manifestCases(perIssuer: false));

/*
 * The per-issuer tokens go through the real service-token service, configured
 * with the raw padded `SERVICE_JWT_SECRETS` string, so the frozen verdicts also
 * pin the map grammar (trimming) and the `iss`-selected secret. A port that
 * agrees with these two tokens binds `iss` to its key the same way.
 */
it('agrees with each committed per-issuer service token', function (string $file, array $meta): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp($meta['verify_now']));

    config([
        'jwt.service.name' => 'auth',
        'jwt.service.secret' => null,
        'jwt.service.secrets' => manifest()['service_secrets'],
    ]);

    $verify = fn (): Claims => app(NativeServiceTokenService::class)->verify(trim(readFixture('tokens/'.$file)));

    if ($meta['outcome'] === 'forged') {
        expect($verify)->toThrow(InvalidSignature::class);

        return;
    }

    expect($verify()->string('scope'))->toBe($meta['scope'])
        ->and($verify()->string('iss'))->toBe($meta['claims']['iss']);
})->with(manifestCases(perIssuer: true));
