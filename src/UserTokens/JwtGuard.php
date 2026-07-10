<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Closure;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/**
 * The `jwt` guard driver: authenticates a request from its bearer token.
 *
 * Pipeline: bearer → verify (RS256 + pinned iss/aud) → required scope →
 * denylist → identity (Eloquent provider when set, else the claims-mode
 * identity class) → optional `token_version` freshness. Any token failure
 * yields a null user (a 401 at the HTTP layer); a {@see KeyLoadFailed}
 * (missing/invalid key) is rethrown so an operator error surfaces as a 500,
 * never a silent 401. The claims are re-resolved whenever the bound request
 * instance changes.
 */
final class JwtGuard implements Guard
{
    use GuardHelpers;

    private ?Claims $payload = null;

    private ?Request $resolvedFor = null;

    /**
     * @param  class-string<ClaimsAuthenticatable>  $identityClass
     * @param  (Closure(Authenticatable): int)|null  $tokenVersion
     */
    public function __construct(
        private readonly UserTokenVerifier $verifier,
        private readonly Denylist $denylist,
        private Request $request,
        private readonly string $requiredScope,
        private readonly string $identityClass,
        private readonly bool $checkDenylist,
        private readonly ?Closure $tokenVersion,
        ?UserProvider $provider = null,
    ) {
        $this->provider = $provider;
    }

    public function user(): ?Authenticatable
    {
        if ($this->user !== null && $this->resolvedFor === $this->request) {
            return $this->user;
        }

        $this->user = null;
        $this->payload = null;
        $this->resolvedFor = $this->request;

        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        $resolved = $this->resolve($token);

        if ($resolved === null) {
            return null;
        }

        [$this->user, $this->payload] = $resolved;

        return $this->user;
    }

    /**
     * Runs the full authentication pipeline, so a denylisted, wrong-scope or
     * stale-version token never validates.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $token = $credentials['token'] ?? null;

        if (! is_string($token)) {
            return false;
        }

        return $this->resolve($token) !== null;
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    /**
     * The verified claims backing the current user, if any.
     */
    public function payload(): ?Claims
    {
        return $this->payload;
    }

    /**
     * @return array{0: Authenticatable, 1: Claims}|null
     */
    private function resolve(string $token): ?array
    {
        try {
            $claims = $this->verifier->verify($token);

            if ($claims->get('scope') !== $this->requiredScope) {
                return null;
            }

            if ($this->checkDenylist) {
                $jti = $claims->get('jti');

                // Fail closed: a token with no string `jti` can never be looked
                // up in the denylist, so it can never be revoked. Reject it
                // rather than skip the check, so a co-issuer sharing the keypair
                // cannot mint irrevocable tokens by omitting `jti`.
                if (! is_string($jti) || $this->denylist->has($jti)) {
                    return null;
                }
            }

            $user = $this->resolveIdentity($claims);

            if ($user === null || ! $this->tokenVersionMatches($claims, $user)) {
                return null;
            }

            return [$user, $claims];
        } catch (KeyLoadFailed $e) {
            // Operator error — never masquerade as an unauthenticated caller.
            throw $e;
        } catch (JwtException) {
            // Covers verification failures and mistyped claims (`tv`,
            // `permissions`) in otherwise validly signed tokens.
            return null;
        }
    }

    private function resolveIdentity(Claims $claims): ?Authenticatable
    {
        $subject = $claims->get('sub');

        if (! is_string($subject)) {
            return null;
        }

        if ($this->provider !== null) {
            return $this->provider->retrieveById($subject);
        }

        return ($this->identityClass)::fromClaims($claims);
    }

    private function tokenVersionMatches(Claims $claims, Authenticatable $user): bool
    {
        if ($this->tokenVersion === null) {
            return true;
        }

        if (! $claims->has('tv')) {
            return false;
        }

        return $claims->int('tv') === ($this->tokenVersion)($user);
    }
}
