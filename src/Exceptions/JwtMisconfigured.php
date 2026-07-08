<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Exceptions;

use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RuntimeException;

/**
 * Raised when user-token configuration is incomplete (empty issuer or
 * audience). Deliberately NOT a {@see JwtException}:
 * guards swallow token exceptions into a 401, but an operator error must
 * surface as a 500. An empty pin would otherwise verify vacuously — two apps
 * sharing a public key with unset audiences would accept each other's tokens.
 */
final class JwtMisconfigured extends RuntimeException
{
    public static function missingIssuer(): self
    {
        return new self('JWT user tokens are misconfigured: JWT_ISSUER is not set.');
    }

    public static function missingAudience(): self
    {
        return new self('JWT user tokens are misconfigured: JWT_AUDIENCE is not set.');
    }
}
