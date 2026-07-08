<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;

it('holds a non-empty secret', function (): void {
    expect((new HmacSecret('shhh'))->value)->toBe('shhh');
});

it('rejects an empty secret', function (): void {
    new HmacSecret('');
})->throws(EmptySecret::class);

it('rejects a PEM used as an HMAC secret', function (): void {
    new HmacSecret(publicKeyPem());
})->throws(PemAsHmacSecret::class);
