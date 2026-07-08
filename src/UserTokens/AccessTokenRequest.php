<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

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
 */
final readonly class AccessTokenRequest
{
    /**
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $extraClaims
     */
    private function __construct(
        public string $subject,
        public ?string $email = null,
        public bool $emailVerified = false,
        public int $tokenVersion = 0,
        public array $permissions = [],
        public array $extraClaims = [],
    ) {}

    public static function for(string|int $subject): self
    {
        return new self((string) $subject);
    }

    public function email(string $email, bool $verified = false): self
    {
        return new self($this->subject, $email, $verified, $this->tokenVersion, $this->permissions, $this->extraClaims);
    }

    public function tokenVersion(int $version): self
    {
        return new self($this->subject, $this->email, $this->emailVerified, $version, $this->permissions, $this->extraClaims);
    }

    public function permissions(string ...$permissions): self
    {
        return new self($this->subject, $this->email, $this->emailVerified, $this->tokenVersion, array_values($permissions), $this->extraClaims);
    }

    /**
     * Merge arbitrary extra claims (an open claim map — registered and known
     * access-token claims always win over these).
     *
     * @param  array<string, mixed>  $claims
     */
    public function withClaims(array $claims): self
    {
        return new self($this->subject, $this->email, $this->emailVerified, $this->tokenVersion, $this->permissions, [...$this->extraClaims, ...$claims]);
    }

    /**
     * The known access-token claim map, ready to hand to the generic mint().
     *
     * @return array<string, mixed>
     */
    public function toClaims(): array
    {
        return [
            ...$this->extraClaims,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'tv' => $this->tokenVersion,
            'permissions' => $this->permissions,
        ];
    }
}
