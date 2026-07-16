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
 *
 * Deliberately not `final`: `jwt.guard.identity` invites a host to swap this
 * class for its own, and extending the shipped identity is the obvious way to
 * do that.
 *
 * @phpstan-consistent-constructor A subclass inherits `fromClaims()`, which
 * builds it with `new static` — so its constructor must keep this signature.
 * Override `fromClaims()` too if you need a different one.
 */
class TokenUser implements Authorizable, ChecksPermissions, ClaimsAuthenticatable
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

    /**
     * `new static`, never `new self`: the guard resolves the *configured*
     * identity class and calls this on it, so binding to the named class here
     * would quietly hand a host back a TokenUser and drop its swap.
     */
    public static function fromClaims(Claims $claims): static
    {
        return new static(
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
