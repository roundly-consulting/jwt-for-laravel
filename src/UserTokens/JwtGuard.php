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
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/**
 * The `jwt` guard driver: authenticates a request from its bearer token.
 *
 * Pipeline: bearer → verify (RS256 + pinned iss/aud) → required scope →
 * denylist → identity (Eloquent provider when set, else the claims-mode
 * identity class) → optional `token_version` freshness. Any failure yields a
 * null user (a 401 at the HTTP layer). The claims are re-resolved whenever the
 * bound request instance changes.
 */
final class JwtGuard implements Guard
{
    use GuardHelpers;

    private ?Claims $payload = null;

    private ?Request $resolvedFor = null;

    private static ?Claims $active = null;

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
        self::$active = null;
        $this->resolvedFor = $this->request;

        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        try {
            $claims = $this->verifier->verify($token);
        } catch (JwtException) {
            return null;
        }

        if ($claims->get('scope') !== $this->requiredScope) {
            return null;
        }

        if ($this->checkDenylist) {
            $jti = $claims->get('jti');

            if (is_string($jti) && $this->denylist->has($jti)) {
                return null;
            }
        }

        $user = $this->resolveIdentity($claims);

        if ($user === null) {
            return null;
        }

        if (! $this->tokenVersionMatches($claims, $user)) {
            return null;
        }

        $this->user = $user;
        $this->payload = $claims;
        self::$active = $claims;

        return $user;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $token = $credentials['token'] ?? null;

        if (! is_string($token)) {
            return false;
        }

        try {
            $this->verifier->verify($token);

            return true;
        } catch (JwtException) {
            return false;
        }
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
     * The claims of the most recently authenticated request in this process.
     */
    public static function active(): ?Claims
    {
        return self::$active;
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
