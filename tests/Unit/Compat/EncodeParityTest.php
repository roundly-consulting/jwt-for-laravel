<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;

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
        : $encoder->encode($meta['claims'], new HmacSecret(manifest()['hmac_secret']), Algorithm::HS256);

    expect($token)->toBe(trim(readFixture('tokens/'.$file)));
})->with(manifestCases());
