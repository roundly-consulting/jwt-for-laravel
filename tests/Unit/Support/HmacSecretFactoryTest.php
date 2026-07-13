<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\WeakSecret;
use RoundlyConsulting\Jwt\Support\HmacSecretFactory;

it('builds a secret from a sufficiently long value', function (): void {
    $value = 'a-secret-of-exactly-32-bytes!!!!';

    expect(strlen($value))->toBe(32)
        ->and(HmacSecretFactory::make($value)->value)->toBe($value);
});

it('rejects an empty secret', function (): void {
    HmacSecretFactory::make('');
})->throws(EmptySecret::class);

it('rejects a secret under 32 bytes as brute-forceable', function (): void {
    HmacSecretFactory::make('a-secret-of-exactly-31-bytes!!!');
})->throws(WeakSecret::class, 'at least 32 random bytes');

it('rejects a PEM used as an HMAC secret (RS256 to HS256 confusion)', function (): void {
    HmacSecretFactory::make(publicKeyPem());
})->throws(PemAsHmacSecret::class);

it('rejects a PEM smuggled behind whitespace or a BOM', function (string $prefix): void {
    HmacSecretFactory::make($prefix.publicKeyPem());
})->with(['whitespace' => "  \n", 'bom' => "\xEF\xBB\xBF"])->throws(PemAsHmacSecret::class);

it('rejects a single repeated byte as low-entropy despite sufficient length', function (): void {
    HmacSecretFactory::make(str_repeat('a', 48));
})->throws(WeakSecret::class, 'single repeated byte');

it('surfaces every rejection as a catchable JwtException', function (string $value): void {
    expect(fn () => HmacSecretFactory::make($value))->toThrow(JwtException::class);
})->with(['empty' => '', 'short' => 'too-short', 'repeated' => str_repeat('z', 40)]);
