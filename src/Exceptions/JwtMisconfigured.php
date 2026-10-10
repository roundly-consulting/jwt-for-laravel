<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Exceptions;

use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RuntimeException;
use SensitiveParameter;

/**
 * Raised when user-token configuration is incomplete (empty issuer or
 * audience), a guard name does not point at a `jwt` guard, a guard's
 * `token_version` cannot be called, or an on/off switch is not a boolean. Deliberately NOT
 * a {@see JwtException}: guards swallow token exceptions into a 401, but an
 * operator error must surface as a 500. An empty pin would otherwise verify vacuously — two apps
 * sharing a public key with unset audiences would accept each other's tokens.
 */
final class JwtMisconfigured extends RuntimeException
{
    /** crypto's `HmacSecret` floor for an HS256 secret (RFC 7518 §3.2). */
    private const int MIN_SECRET_BYTES = 32;

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

    /**
     * An access-token request addressed to one audience, minted through a guard
     * that serves another. Re-addressing it silently would hand the caller a token
     * for an audience it never asked for.
     */
    public static function conflictingAudience(string $guard, string $requested, string $expected): self
    {
        return new self("The access-token request names audience [{$requested}], but jwt guard [{$guard}] mints for [{$expected}].");
    }

    /**
     * A configured value of the wrong shape — named by key, so a typo fails loudly at
     * the read that would otherwise have quietly fallen back. Only non-secret keys
     * reach here with a string (a class name, a scope, a blank prefix), so a string is
     * echoed; anything else renders as its type.
     */
    public static function invalidValue(string $key, string $expectation, mixed $value): self
    {
        $given = match (true) {
            is_string($value) => "[{$value}]",
            is_int($value) || is_bool($value) => '['.var_export($value, true).']',
            default => get_debug_type($value),
        };

        return new self("Configuration value [{$key}] must be {$expectation}, {$given} given.");
    }

    public static function malformedSecretPair(): self
    {
        return new self('Configuration value [jwt.service.secrets] must be a comma-separated list of issuer:secret pairs, a malformed pair was given.');
    }

    /**
     * An issuer named twice in the per-issuer map, first at 1-based entry `$first`
     * and again at `$second`. Never names a secret: the issuer is printed only when
     * it looks like one ({@see self::looksLikeIssuer()}). A pair written
     * `secret:issuer` puts a secret in the issuer slot, so anything else is withheld
     * and the colliding entries are named by position instead.
     */
    public static function duplicateSecretIssuer(#[SensitiveParameter] string $issuer, int $first, int $second): self
    {
        if (self::looksLikeIssuer($issuer)) {
            return new self("Configuration value [jwt.service.secrets] names issuer [{$issuer}] more than once, each issuer needs exactly one secret.");
        }

        return new self("Configuration value [jwt.service.secrets]: entries {$first} and {$second} name the same issuer, each issuer needs exactly one secret. The issuer is not shown as it may be a secret, check each entry is written issuer:secret.");
    }

    /**
     * Service-name shaped (`^[A-Za-z0-9][A-Za-z0-9._-]*$`) AND under the 32 bytes
     * crypto's `HmacSecret` demands of an HS256 secret: a value that short can
     * never be a usable secret, so printing it leaks nothing.
     */
    private static function looksLikeIssuer(#[SensitiveParameter] string $issuer): bool
    {
        return strlen($issuer) < self::MIN_SECRET_BYTES
            && preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/', $issuer) === 1;
    }
}
