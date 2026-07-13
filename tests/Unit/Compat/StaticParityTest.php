<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;

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
        : HmacSecret::fromString(manifest()['hmac_secret']);

    if ($meta['outcome'] === 'expired') {
        expect(fn () => $decoder->decode($token, $key, $algorithm, 0))->toThrow(TokenExpired::class);

        return;
    }

    $claims = $decoder->decode($token, $key, $algorithm, 0);

    expect($claims->string('scope'))->toBe($meta['scope']);
})->with(manifestCases());
