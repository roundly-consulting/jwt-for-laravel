<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;

/**
 * The `service-jwt` guard driver: authenticates an internal caller from its
 * bearer service token.
 *
 * A rejected token yields a null user (401). A {@see ServiceAuthMisconfigured}
 * (missing secret) is not caught here, so it propagates to a 500 — an operator
 * error must never masquerade as an unauthenticated caller.
 *
 * An identity handed to {@see setUser()} (Laravel's `actingAs($identity,
 * 'service')`) is kept until {@see forgetUser()}, across request changes too;
 * a bearer-resolved caller is re-resolved whenever the request instance changes.
 */
final class ServiceGuard implements Guard
{
    use GuardHelpers;

    private ?Claims $payload = null;

    private ?Request $resolvedFor = null;

    /** Whether {@see $user} came from {@see setUser()} rather than a bearer token. */
    private bool $userWasSet = false;

    public function __construct(
        private readonly ServiceTokenVerifier $verifier,
        private Request $request,
    ) {}

    public function user(): ?Authenticatable
    {
        if ($this->hasUser()) {
            return $this->user;
        }

        $this->forgetUser();
        $this->resolvedFor = $this->request;

        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        try {
            $claims = $this->verifier->verify($token);
        } catch (ServiceAuthMisconfigured $e) {
            // Surface misconfiguration as a 500 — never a silent 401.
            throw $e;
        } catch (JwtException) {
            return null;
        }

        $this->user = ServiceIdentity::fromClaims($claims);
        $this->payload = $claims;

        return $this->user;
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

    /**
     * Only the caller this guard holds for the *current* request (or one set
     * explicitly) — never one left over from an earlier request.
     */
    public function hasUser(): bool
    {
        return $this->user !== null && ($this->userWasSet || $this->resolvedFor === $this->request);
    }

    /**
     * Authenticate as the given identity until {@see forgetUser()}. A
     * {@see ServiceIdentity}'s claims back {@see payload()}; any other user
     * leaves it null.
     */
    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;
        $this->payload = $user instanceof ServiceIdentity ? $user->claims() : null;
        $this->userWasSet = true;

        return $this;
    }

    public function forgetUser(): static
    {
        $this->user = null;
        $this->payload = null;
        $this->userWasSet = false;
        $this->resolvedFor = null;

        return $this;
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    public function payload(): ?Claims
    {
        return $this->payload;
    }
}
