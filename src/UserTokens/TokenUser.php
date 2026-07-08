<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Foundation\Auth\Access\Authorizable as AuthorizableTrait;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ChecksPermissions;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;

/**
 * A claims-backed identity used when no Eloquent user provider is configured.
 *
 * Carries the verified token's claims and exposes the `sub` as the auth
 * identifier plus a `permissions`-claim membership check that the optional
 * `Gate::before` hook consults.
 */
final class TokenUser implements Authorizable, ChecksPermissions, ClaimsAuthenticatable
{
    use AuthorizableTrait;

    /**
     * @param  list<string>  $permissions
     */
    public function __construct(
        private readonly Claims $claims,
        private readonly string $identifier,
        private readonly array $permissions,
    ) {}

    public static function fromClaims(Claims $claims): self
    {
        return new self(
            $claims,
            $claims->string('sub'),
            $claims->has('permissions') ? $claims->list('permissions') : [],
        );
    }

    public function claims(): Claims
    {
        return $this->claims;
    }

    public function hasPermission(string $ability): bool
    {
        return in_array($ability, $this->permissions, true);
    }

    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    public function getAuthIdentifier(): string
    {
        return $this->identifier;
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
        // Token identities are stateless; remember-me does not apply.
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}
