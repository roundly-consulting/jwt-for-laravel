<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Keys;

use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\WeakSecret;

/**
 * A shared secret used to sign and verify HS256 service tokens.
 *
 * Three defences live in the constructor: an empty secret is rejected
 * outright; a value that looks like a PEM is rejected so an RSA public key can
 * never be smuggled in as an HMAC key (the classic RS256→HS256 confusion
 * attack); and a secret under 256 bits is rejected as brute-forceable
 * (RFC 7518 §3.2 requires HS256 keys of at least the hash size).
 */
final readonly class HmacSecret
{
    private const MIN_BYTES = 32;

    public function __construct(#[\SensitiveParameter] public string $value)
    {
        if ($value === '') {
            throw new EmptySecret('The HMAC secret is empty.');
        }

        if (str_starts_with($value, '-----BEGIN')) {
            throw new PemAsHmacSecret('A PEM-encoded key cannot be used as an HMAC secret.');
        }

        if (strlen($value) < self::MIN_BYTES) {
            throw new WeakSecret('The HMAC secret must be at least 32 bytes; generate one with `openssl rand -base64 48`.');
        }
    }
}
