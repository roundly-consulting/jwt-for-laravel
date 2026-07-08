<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\Jwt\Jose\Claims;

/**
 * The authenticated identity of a calling service, backed by its verified
 * service-token claims. The auth identifier is the calling service's `iss`.
 */
final class ServiceIdentity implements Authenticatable
{
    public function __construct(
        private readonly Claims $claims,
        private readonly string $issuer,
    ) {}

    public static function fromClaims(Claims $claims): self
    {
        return new self($claims, $claims->string('iss'));
    }

    public function claims(): Claims
    {
        return $this->claims;
    }

    public function getAuthIdentifierName(): string
    {
        return 'iss';
    }

    public function getAuthIdentifier(): string
    {
        return $this->issuer;
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void
    {
        // Service identities are stateless.
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}
