<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use DateTimeInterface;
use InvalidArgumentException;

/**
 * An immutable, fluent builder for the known fields of an access token.
 *
 * Replaces the 5-positional-argument `mintAccessToken` footgun with a
 * left-to-right, self-documenting API:
 *
 * ```php
 * AccessTokenRequest::for($user->id)
 *     ->email($user->email, verified: $user->hasVerifiedEmail())
 *     ->tokenVersion($user->token_version)
 *     ->permissions('posts.view', 'posts.edit')
 *     ->withClaims(['org' => 42]);
 * ```
 *
 * `audience()` and `ttl()` are minting parameters, not payload: they steer the
 * issuer and never appear in {@see toClaims()}. The OIDC session claims
 * (`sid`, `amr`, `auth_time`) are emitted only when set, so a request that
 * never touches them mints exactly the payload it always did.
 */
final readonly class AccessTokenRequest
{
    /**
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $extraClaims
     * @param  list<string>|null  $authMethods
     */
    private function __construct(
        public string $subject,
        public ?string $email = null,
        public bool $emailVerified = false,
        public int $tokenVersion = 0,
        public array $permissions = [],
        public array $extraClaims = [],
        public ?string $audience = null,
        public ?int $ttl = null,
        public ?string $sessionId = null,
        public ?array $authMethods = null,
        public ?int $authTime = null,
    ) {}

    public static function for(string|int $subject): self
    {
        return new self((string) $subject);
    }

    public function email(string $email, bool $verified = false): self
    {
        return $this->with(email: $email, emailVerified: $verified);
    }

    public function tokenVersion(int $version): self
    {
        return $this->with(tokenVersion: $version);
    }

    public function permissions(string ...$permissions): self
    {
        return $this->with(permissions: array_values($permissions));
    }

    /**
     * Merge arbitrary extra claims (an open claim map — registered and known
     * access-token claims always win over these).
     *
     * @param  array<string, mixed>  $claims
     */
    public function withClaims(array $claims): self
    {
        return $this->with(extraClaims: [...$this->extraClaims, ...$claims]);
    }

    /**
     * Mint for this audience instead of the configured `jwt.audience` — e.g.
     * `Jwt::audienceFor('clients')` for a second guard.
     */
    public function audience(string $audience): self
    {
        return $this->with(audience: $audience);
    }

    /**
     * Lifetime in seconds, overriding the configured `jwt.ttl`.
     *
     * @throws InvalidArgumentException when below one second.
     */
    public function ttl(int $seconds): self
    {
        if ($seconds < 1) {
            throw new InvalidArgumentException('An access token TTL must be at least one second.');
        }

        return $this->with(ttl: $seconds);
    }

    /**
     * The OIDC `sid` claim: the login session this token belongs to.
     *
     * @throws InvalidArgumentException when empty.
     */
    public function sessionId(string|int $sessionId): self
    {
        $sessionId = (string) $sessionId;

        if ($sessionId === '') {
            throw new InvalidArgumentException('A session id must not be empty.');
        }

        return $this->with(sessionId: $sessionId);
    }

    /**
     * The RFC 8176 `amr` claim: how the subject authenticated (`pwd`, `otp`,
     * `hwk`, `mfa`, …). Duplicates are dropped, first occurrence wins.
     *
     * @throws InvalidArgumentException when no method, or an empty one, is given.
     */
    public function authMethods(string ...$methods): self
    {
        if ($methods === [] || in_array('', $methods, true)) {
            throw new InvalidArgumentException('Authentication methods must be a non-empty list of non-empty strings.');
        }

        return $this->with(authMethods: array_values(array_unique($methods)));
    }

    /**
     * The OIDC `auth_time` claim: when the subject actually authenticated (unix
     * seconds), which a refreshed token carries forward unchanged.
     */
    public function authTime(int|DateTimeInterface $time): self
    {
        return $this->with(authTime: $time instanceof DateTimeInterface ? $time->getTimestamp() : $time);
    }

    /**
     * The known access-token claim map, ready to hand to the generic mint().
     *
     * @return array<string, mixed>
     */
    public function toClaims(): array
    {
        $claims = [
            ...$this->extraClaims,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'tv' => $this->tokenVersion,
            'permissions' => $this->permissions,
        ];

        if ($this->sessionId !== null) {
            $claims['sid'] = $this->sessionId;
        }

        if ($this->authMethods !== null) {
            $claims['amr'] = $this->authMethods;
        }

        if ($this->authTime !== null) {
            $claims['auth_time'] = $this->authTime;
        }

        return $claims;
    }

    /**
     * A copy with the named fields replaced — the one place every wither goes
     * through, so adding a field never means re-threading every constructor call.
     *
     * @param  list<string>|null  $permissions
     * @param  array<string, mixed>|null  $extraClaims
     * @param  list<string>|null  $authMethods
     */
    private function with(
        ?string $email = null,
        ?bool $emailVerified = null,
        ?int $tokenVersion = null,
        ?array $permissions = null,
        ?array $extraClaims = null,
        ?string $audience = null,
        ?int $ttl = null,
        ?string $sessionId = null,
        ?array $authMethods = null,
        ?int $authTime = null,
    ): self {
        return new self(
            $this->subject,
            $email ?? $this->email,
            $emailVerified ?? $this->emailVerified,
            $tokenVersion ?? $this->tokenVersion,
            $permissions ?? $this->permissions,
            $extraClaims ?? $this->extraClaims,
            $audience ?? $this->audience,
            $ttl ?? $this->ttl,
            $sessionId ?? $this->sessionId,
            $authMethods ?? $this->authMethods,
            $authTime ?? $this->authTime,
        );
    }
}
