<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;

final class KeyLoadFailed extends JwtException
{
    public static function privateKeyMissing(string $path): self
    {
        return new self(
            "JWT private key not found at [{$path}]. Run `php artisan jwt:generate-keys` on the issuer app, or set JWT_PRIVATE_KEY_PATH."
        );
    }

    public static function publicKeyMissing(string $path): self
    {
        return new self(
            "JWT public key not found at [{$path}]. Copy the issuer's `jwt-public.pem` there, or set JWT_PUBLIC_KEY_PATH."
        );
    }

    public static function privateKeyNotConfigured(): self
    {
        return new self(
            'No JWT private key path configured. Set JWT_PRIVATE_KEY_PATH to mint user tokens.'
        );
    }

    public static function publicKeyNotConfigured(): self
    {
        return new self(
            'No JWT public key path configured. Set JWT_PUBLIC_KEY_PATH to verify user tokens.'
        );
    }

    /**
     * The configured PEM was rejected by the crypto package — it is not a valid
     * PEM, not an RSA key, or too weak. RS256 requires an RSA key of at least
     * 2048 bits; the crypto message states the precise reason.
     */
    public static function unusable(string $kind, CryptoException $previous): self
    {
        return new self(
            "The configured {$kind} JWT key is unusable: {$previous->getMessage()} RS256 requires an RSA key of a minimum of 2048 bits.",
            previous: $previous,
        );
    }
}
