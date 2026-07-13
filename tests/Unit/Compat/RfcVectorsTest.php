<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Jose\Decoder;

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

/**
 * @return array<string, mixed>
 */
function rfcVector(string $file): array
{
    return json_decode(readFixture('vectors/rfc/'.$file), true, 512, JSON_THROW_ON_ERROR);
}

it('verifies the RFC 7515 A.1 HS256 vector with the external key', function (): void {
    $vector = rfcVector('hs256-rfc7515-a1.json');
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp($vector['verify_now']));

    $key = HmacSecret::fromString(Base64Url::decode($vector['hmac_key_b64url']));
    $claims = (new Decoder)->decode($vector['jwt'], $key, Algorithm::HS256, 0);

    expect($claims->string('iss'))->toBe($vector['expected_iss'])
        ->and($claims->int('exp'))->toBe($vector['expected_exp']);
});

it('verifies the RFC 7515 A.2 RS256 vector with the external key', function (): void {
    $vector = rfcVector('rs256-rfc7515-a2.json');
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp($vector['verify_now']));

    $key = RsaKey::public(readFixture('keys/'.$vector['public_key_pem']));
    $claims = (new Decoder)->decode($vector['jwt'], $key, Algorithm::RS256, 0);

    expect($claims->string('iss'))->toBe($vector['expected_iss'])
        ->and($claims->int('exp'))->toBe($vector['expected_exp']);
});
