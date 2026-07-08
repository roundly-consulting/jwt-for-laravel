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
 */
final class ServiceGuard implements Guard
{
    use GuardHelpers;

    private ?Claims $payload = null;

    private ?Request $resolvedFor = null;

    public function __construct(
        private readonly ServiceTokenVerifier $verifier,
        private Request $request,
    ) {}

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
