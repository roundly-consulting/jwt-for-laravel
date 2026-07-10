<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Base64Url;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnencodableClaims;

function decodeSegment(string $token, int $index): array
{
    $segment = explode('.', $token)[$index];

    return json_decode(Base64Url::decode($segment), true);
}

it('encodes an RS256 token with the RSA private key', function (): void {
    $token = (new Encoder)->encode(['sub' => 'a'], rsaPrivateKey(), Algorithm::RS256);

    expect(explode('.', $token))->toHaveCount(3)
        ->and(decodeSegment($token, 0))->toBe(['typ' => 'JWT', 'alg' => 'RS256'])
        ->and(decodeSegment($token, 1))->toBe(['sub' => 'a']);
});

it('encodes an HS256 token with the HMAC secret', function (): void {
    $token = (new Encoder)->encode(['sub' => 'a'], hmacSecret(), Algorithm::HS256);

    expect(decodeSegment($token, 0))->toBe(['typ' => 'JWT', 'alg' => 'HS256']);
});

it('emits a kid header only when provided', function (): void {
    $withKid = (new Encoder)->encode([], rsaPrivateKey(), Algorithm::RS256, 'key-1');
    $withoutKid = (new Encoder)->encode([], rsaPrivateKey(), Algorithm::RS256);

    expect(decodeSegment($withKid, 0))->toBe(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'key-1'])
        ->and(decodeSegment($withoutKid, 0))->not->toHaveKey('kid');
});

it('rejects signing RS256 with an HMAC secret', function (): void {
    (new Encoder)->encode([], hmacSecret(), Algorithm::RS256);
})->throws(AlgorithmMismatch::class);

it('rejects signing HS256 with an RSA private key', function (): void {
    (new Encoder)->encode([], rsaPrivateKey(), Algorithm::HS256);
})->throws(AlgorithmMismatch::class);

it('wraps a non-UTF-8 claim in a package exception', function (): void {
    // A host-supplied extra claim with invalid UTF-8 bytes would throw a bare
    // JsonException; it must surface as a JwtException so minting stays inside
    // the package's error contract.
    (new Encoder)->encode(['bad' => "\xB1\x31"], rsaPrivateKey(), Algorithm::RS256);
})->throws(UnencodableClaims::class);

it('surfaces the unencodable-claim error as a catchable JwtException', function (): void {
    expect(fn () => (new Encoder)->encode(['bad' => "\xB1\x31"], rsaPrivateKey(), Algorithm::RS256))
        ->toThrow(JwtException::class);
});

it('is deterministic for the same claims and key', function (): void {
    $encoder = new Encoder;

    expect($encoder->encode(['sub' => 'a'], rsaPrivateKey(), Algorithm::RS256))
        ->toBe($encoder->encode(['sub' => 'a'], rsaPrivateKey(), Algorithm::RS256));
});
