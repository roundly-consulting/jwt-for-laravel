<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Exceptions;

use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RuntimeException;

/**
 * Raised when user-token configuration is incomplete (empty issuer or
 * audience), a guard name does not point at a `jwt` guard, or a guard's
 * `token_version` cannot be called. Deliberately NOT
 * a {@see JwtException}: guards swallow token exceptions into a 401, but an
 * operator error must surface as a 500. An empty pin would otherwise verify vacuously — two apps
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

    public static function notAJwtGuard(string $guard): self
    {
        return new self("Auth guard [{$guard}] is not configured with the jwt driver.");
    }

    /**
     * A configured `token_version` the guard cannot call. Ignoring it would switch
     * the freshness check off, so a bumped version would revoke nothing.
     */
    public static function invalidTokenVersion(string $guard): self
    {
        return new self("The token_version of jwt guard [{$guard}] must be an invokable class-string or a closure.");
    }
}
