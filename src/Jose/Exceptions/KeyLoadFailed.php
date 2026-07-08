<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

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

    public static function unreadable(string $kind, string $path): self
    {
        return new self("Unable to load the {$kind} JWT key from [{$path}]: it is not a valid PEM.");
    }

    public static function notRsa(string $kind): self
    {
        return new self("The configured {$kind} JWT key is not an RSA key; RS256 requires RSA.");
    }

    public static function tooSmall(string $kind, int $bits): self
    {
        return new self("The {$kind} RSA JWT key is {$bits} bits; a minimum of 2048 bits is required.");
    }
}
