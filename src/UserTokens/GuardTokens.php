<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\JwtManager;

/**
 * One `jwt` guard — `Jwt::guard('clients')`. Mints and verifies for the guard's
 * own audience (`auth.guards.<name>.audience`, else `jwt.audience`), exposes its
 * effective settings, and reads the current request's claims on it.
 *
 * Scoped: a token minted for another guard's audience fails `verify()` here, and
 * `claims()` never answers with another guard's user. Mints and verifies go
 * through the {@see JwtManager}, so events fire and `Jwt::fake()` records them.
 */
final readonly class GuardTokens
{
    public function __construct(
        private JwtManager $manager,
        private Container $container,
        private JwtGuardSettings $settings,
    ) {}

    /**
     * Mint a token of any scope for this guard's audience.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, Scope|string $scope, int $ttl, array $extraClaims = []): IssuedToken
    {
        return $this->manager->mint($subject, $scope, $ttl, $extraClaims, $this->settings->audience);
    }

    /**
     * Mint an access token for this guard's audience. A request that already names
     * a different audience is refused rather than silently re-addressed.
     *
     * @throws JwtMisconfigured when the request's audience is not this guard's.
     */
    public function mintAccessToken(AccessTokenRequest $request): IssuedToken
    {
        if ($request->audience !== null && $request->audience !== $this->settings->audience) {
            throw JwtMisconfigured::conflictingAudience($this->settings->guard, $request->audience, $this->settings->audience);
        }

        return $this->manager->mintAccessToken($request->audience($this->settings->audience));
    }

    /**
     * Verify a user token against this guard's audience (signature, expiry, pinned
     * issuer), dispatching `TokenVerificationFailed` on failure.
     *
     * @throws JwtException
     */
    public function verify(string $jwt): Claims
    {
        return $this->manager->verify($jwt, $this->settings->audience);
    }

    /**
     * The verified claims of the current request on this guard, or null when it has
     * no user. Resolved through the auth manager's per-request guard — never static
     * state — so long-lived workers (Octane, queues) can't leak one request's claims
     * into the next.
     */
    public function claims(): ?Claims
    {
        $guard = $this->container->make(AuthFactory::class)->guard($this->settings->guard);

        return $guard instanceof JwtGuard && $guard->user() !== null ? $guard->payload() : null;
    }

    /**
     * The guard's effective options — exactly what the `jwt` driver enforces.
     */
    public function settings(): JwtGuardSettings
    {
        return $this->settings;
    }

    /**
     * The audience tokens for this guard are minted for and verified against.
     */
    public function audience(): string
    {
        return $this->settings->audience;
    }
}
