<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Events\TokenVerificationFailed;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceCaller;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;

/**
 * The one obvious entry point behind the `Jwt` facade.
 *
 * A thin coordinator: every method delegates to a contract resolved lazily from
 * the container, so a verify-only app (no private key) can still resolve the
 * manager, and host overrides of any contract are always honoured. No token
 * logic lives here.
 */
final class JwtManager
{
    public function __construct(private readonly Container $container) {}

    public function mintAccessToken(AccessTokenRequest $request): IssuedToken
    {
        return $this->issuer()->mintAccessToken($request);
    }

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, string $scope, int $ttl, array $extraClaims = []): IssuedToken
    {
        return $this->issuer()->mint($subject, $scope, $ttl, $extraClaims);
    }

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    public function mintChallengeToken(string $subject, array $extraClaims = []): IssuedToken
    {
        return $this->issuer()->mintChallengeToken($subject, $extraClaims);
    }

    public function mintEmailVerifyToken(string $subject, string $email): IssuedToken
    {
        return $this->issuer()->mintEmailVerifyToken($subject, $email);
    }

    /**
     * Verify an RS256 user token, dispatching {@see TokenVerificationFailed} on
     * failure. This is the explicit verify path; the guard's silent per-request
     * resolution does not emit the event.
     *
     * @throws JwtException
     */
    public function verify(string $jwt): Claims
    {
        try {
            return $this->verifier()->verify($jwt);
        } catch (JwtException $e) {
            $this->events()?->dispatch(new TokenVerificationFailed($e->getMessage(), $e::class));

            throw $e;
        }
    }

    public function service(): NativeServiceTokenService
    {
        return $this->container->make(NativeServiceTokenService::class);
    }

    public function caller(): ServiceCaller
    {
        return $this->container->make(ServiceCaller::class);
    }

    public function denylist(): Denylist
    {
        return $this->container->make(Denylist::class);
    }

    /**
     * Log out (denylist) a freshly issued token until its own expiry.
     */
    public function logout(IssuedToken $token): void
    {
        $this->denylist()->denyToken($token);
    }

    /**
     * Denylist a token from its verified claims (reads `jti` + `exp`).
     *
     * @throws ClaimMismatch when `jti`/`exp` are absent or mistyped.
     */
    public function denyClaims(Claims $claims): void
    {
        $this->denylist()->deny(
            $claims->string('jti'),
            CarbonImmutable::createFromTimestamp($claims->int('exp')),
        );
    }

    /**
     * The verified claims of the current request, or null when unauthenticated.
     *
     * Resolved through the auth manager's per-request `jwt` guard(s) — never
     * static state — so long-lived workers (Octane, queues) can't leak one
     * request's claims into the next.
     */
    public function claims(): ?Claims
    {
        $auth = $this->container->make(AuthFactory::class);

        /** @var array<string, array<string, mixed>> $guards */
        $guards = (array) $this->container->make(ConfigRepository::class)->get('auth.guards', []);

        foreach ($guards as $name => $config) {
            if (($config['driver'] ?? null) !== 'jwt') {
                continue;
            }

            $guard = $auth->guard($name);

            if ($guard instanceof JwtGuard && $guard->user() !== null) {
                return $guard->payload();
            }
        }

        return null;
    }

    private function issuer(): UserTokenIssuer
    {
        return $this->container->make(UserTokenIssuer::class);
    }

    private function verifier(): UserTokenVerifier
    {
        return $this->container->make(UserTokenVerifier::class);
    }

    private function events(): ?Dispatcher
    {
        return $this->container->bound(Dispatcher::class)
            ? $this->container->make(Dispatcher::class)
            : null;
    }
}
