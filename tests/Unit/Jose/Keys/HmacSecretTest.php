<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\WeakSecret;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;

it('holds a sufficiently long secret', function (): void {
    $value = 'a-secret-of-exactly-32-bytes!!!!';

    expect(strlen($value))->toBe(32)
        ->and((new HmacSecret($value))->value)->toBe($value);
});

it('rejects an empty secret', function (): void {
    new HmacSecret('');
})->throws(EmptySecret::class);

it('rejects a secret under 32 bytes as brute-forceable', function (): void {
    new HmacSecret('a-secret-of-exactly-31-bytes!!!');
})->throws(WeakSecret::class, 'at least 32 random bytes');

it('rejects a PEM used as an HMAC secret', function (): void {
    new HmacSecret(publicKeyPem());
})->throws(PemAsHmacSecret::class);

it('rejects a single repeated byte as low-entropy despite sufficient length', function (): void {
    new HmacSecret(str_repeat('a', 48));
})->throws(WeakSecret::class, 'single repeated byte');
