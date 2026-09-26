<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Exceptions;

use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RuntimeException;

/**
 * Raised when service-to-service auth is misconfigured (e.g. a missing shared
 * secret). Deliberately NOT a {@see JwtException}:
 * the service guard rethrows it so it surfaces as a 500, never a silent 401 —
 * a misconfiguration is an operator error, not a rejected caller.
 */
final class ServiceAuthMisconfigured extends RuntimeException
{
    public static function missingSecret(): self
    {
        return new self('Service token auth is misconfigured: SERVICE_JWT_SECRET is not set.');
    }

    public static function invalidSecret(string $reason): self
    {
        return new self("Service token auth is misconfigured: {$reason}");
    }

    public static function missingIssuer(): self
    {
        return new self('Service token auth is misconfigured: JWT_SERVICE_ISSUER is not set and no service name (JWT_SERVICE_NAME) could be derived.');
    }

    public static function missingAudience(): self
    {
        return new self('Service token auth is misconfigured: no audience given and JWT_SERVICE_AUDIENCE is not set.');
    }

    public static function missingServiceName(): self
    {
        return new self('Service token auth is misconfigured: no service name — set JWT_SERVICE_NAME (jwt.service.name), so inbound audiences can be pinned.');
    }

    public static function ownIssuerSecretMissing(string $issuer): self
    {
        return new self("Service token auth is misconfigured: SERVICE_JWT_SECRETS has no entry for this service's own issuer [{$issuer}].");
    }

    /**
     * @param  list<string>  $claims
     */
    public static function reservedClaims(array $claims): self
    {
        return new self('Service token auth is misconfigured: ['.implode(', ', $claims).'] are registered claims and cannot be supplied by a caller.');
    }
}
