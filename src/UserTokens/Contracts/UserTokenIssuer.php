<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\Scope;

interface UserTokenIssuer
{
    /**
     * Mint a signed RS256 user token for the given subject and scope.
     *
     * Pass a {@see Scope} case for a built-in scope, or any string for a custom
     * one. `$audience` overrides the configured `jwt.audience` for this token
     * (null keeps the configured one; an empty string is a misconfiguration).
     *
     * `$ttl` is not bounded: a ttl of 0 or below mints a token that is already
     * expired (0 still verifies within `jwt.leeway`), which is how a test builds
     * an expired token. Every config TTL and `AccessTokenRequest::ttl()` require
     * at least 1.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, Scope|string $scope, int $ttl, array $extraClaims = [], ?string $audience = null): IssuedToken;

    /**
     * Mint an access token (`scope=access`) from a fluent request, honouring
     * the request's audience and TTL and falling back to the configured
     * `jwt.audience` / `jwt.ttl`.
     */
    public function mintAccessToken(AccessTokenRequest $request): IssuedToken;

    /**
     * Mint a 2FA challenge token (`scope=2fa_pending`) using the configured
     * `challenge_ttl`.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function mintChallengeToken(string $subject, array $extraClaims = []): IssuedToken;

    /**
     * Mint an email-verification token (`scope=email_verify`) carrying the
     * address, using the configured `verify_ttl`.
     */
    public function mintEmailVerifyToken(string $subject, string $email): IssuedToken;
}
