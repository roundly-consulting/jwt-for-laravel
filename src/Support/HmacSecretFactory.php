<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\WeakKeyException;
use RoundlyConsulting\Jwt\Jose\Exceptions\EmptySecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\PemAsHmacSecret;
use RoundlyConsulting\Jwt\Jose\Exceptions\WeakSecret;
use SensitiveParameter;

/**
 * Builds a validated HS256 secret from the host's own config, translating the
 * crypto package's single {@see WeakKeyException} back into this package's
 * precise exceptions, which are its public error contract.
 *
 * The guards themselves live in crypto: an empty secret is rejected; a value
 * carrying public-key material is rejected so an RSA public key can never be
 * smuggled in as an HMAC key (the classic RS256→HS256 confusion attack); a
 * secret under 256 bits is rejected as brute-forceable (RFC 7518 §3.2); and a
 * single-repeated-byte secret is rejected as obviously low-entropy. Crypto also
 * catches smuggles this package used to miss (a PEM behind whitespace/BOM, raw
 * DER key bytes) — those surface as {@see WeakSecret}.
 */
final class HmacSecretFactory
{
    /**
     * @throws EmptySecret|PemAsHmacSecret|WeakSecret
     */
    public static function make(#[SensitiveParameter] string $value): HmacSecret
    {
        try {
            return HmacSecret::fromString($value);
        } catch (WeakKeyException $e) {
            throw match (true) {
                $value === '' => new EmptySecret('The HMAC secret is empty.', previous: $e),
                self::looksLikePem($value) => new PemAsHmacSecret('A PEM-encoded key cannot be used as an HMAC secret.', previous: $e),
                default => new WeakSecret($e->getMessage(), previous: $e),
            };
        }
    }

    /**
     * A textual PEM smuggle, robust to a leading BOM and/or whitespace — the same
     * shape crypto reports as `pemAsSecret`.
     */
    private static function looksLikePem(#[SensitiveParameter] string $value): bool
    {
        $text = str_starts_with($value, "\xEF\xBB\xBF") ? substr($value, 3) : $value;

        return str_starts_with(ltrim($text), '-----BEGIN');
    }
}
