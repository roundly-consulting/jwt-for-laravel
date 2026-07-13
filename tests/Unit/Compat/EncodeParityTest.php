<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Jwt\Jose\Encoder;

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

/**
 * The native encoder must reproduce each committed token byte-for-byte from its
 * recorded claim set — locking the compact-JWS output (header key order, JSON
 * byte form, deterministic signatures) against regressions.
 */
it('reproduces each committed token byte-for-byte', function (string $file, array $meta): void {
    $encoder = new Encoder;

    $token = $meta['alg'] === 'RS256'
        ? $encoder->encode($meta['claims'], rsaPrivateKey(), Algorithm::RS256)
        : $encoder->encode($meta['claims'], HmacSecret::fromString(manifest()['hmac_secret']), Algorithm::HS256);

    expect($token)->toBe(trim(readFixture('tokens/'.$file)));
})->with(manifestCases());
