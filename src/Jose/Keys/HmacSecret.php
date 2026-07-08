<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Keys;

use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;

/**
 * A shared secret used to sign and verify HS256 service tokens.
 *
 * Two defences live in the constructor: an empty secret is rejected outright,
 * and a value that looks like a PEM is rejected so an RSA public key can never
 * be smuggled in as an HMAC key (the classic RS256→HS256 confusion attack).
 */
final readonly class HmacSecret
{
    public function __construct(#[\SensitiveParameter] public string $value)
    {
        if ($value === '') {
            throw new EmptySecret('The HMAC secret is empty.');
        }

        if (str_starts_with($value, '-----BEGIN')) {
            throw new PemAsHmacSecret('A PEM-encoded key cannot be used as an HMAC secret.');
        }
    }
}
