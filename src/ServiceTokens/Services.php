<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use DateInterval;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Denylist\RevocationCheck;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenRevoked;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuerWithOptions;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\Testing\RecordingServices;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use SensitiveParameter;

/**
 * HS256 machine-to-machine tokens — `Jwt::services()`. Issues and verifies through
 * the {@see ServiceTokenIssuer} / {@see ServiceTokenVerifier} contracts resolved
 * from the container per call, so a host rebinding either one is honoured.
 *
 * Not final: {@see RecordingServices} extends it under `Jwt::fake()`.
 */
readonly class Services
{
    public function __construct(
        protected Container $container,
    ) {}

    /**
     * Issue a service token for the audience (default `jwt.service.audience`).
     * `$claims` adds caller-defined, non-registered claims; a registered name is
     * rejected, never merged.
     *
     * `$ttl` overrides `jwt.service.ttl` for this token: whole seconds, an int or a
     * `DateInterval` / `CarbonInterval`, from 1 to `jwt.service.max_ttl`. `$subject`
     * sets the `sub` claim (non-empty, ≤ 255 bytes, no control characters or
     * surrounding whitespace) — the only way a service token carries one. Either
     * option needs a bound issuer implementing {@see ServiceTokenIssuerWithOptions};
     * any other one is refused rather than allowed to drop them silently.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws ServiceAuthMisconfigured
     */
    public function issue(
        ?string $audience = null,
        array $claims = [],
        int|DateInterval|null $ttl = null,
        ?string $subject = null,
    ): IssuedToken {
        $issuer = $this->container->make(ServiceTokenIssuer::class);

        if ($ttl === null && $subject === null) {
            return $issuer->issue($audience, $claims);
        }

        if (! $issuer instanceof ServiceTokenIssuerWithOptions) {
            throw ServiceAuthMisconfigured::issuerLacksOptions($issuer::class);
        }

        return $issuer->issue($audience, $claims, $ttl, $subject);
    }

    /**
     * Verify an inbound service token addressed to this service. With
     * `$checkDenylist` its `jti` must also be absent from the denylist, so a token
     * revoked with `Jwt::logout()` / `Jwt::denyClaims()` is refused; the default
     * (false) leaves the result exactly as before.
     *
     * @throws TokenRevoked when `$checkDenylist` is on and the token was revoked.
     * @throws ClaimMismatch when `$checkDenylist` is on and the token carries no `jti`.
     * @throws JwtException|ServiceAuthMisconfigured
     */
    public function verify(#[SensitiveParameter] string $jwt, bool $checkDenylist = false): Claims
    {
        $claims = $this->container->make(ServiceTokenVerifier::class)->verify($jwt);

        return $checkDenylist
            ? RevocationCheck::assertActive($this->container->make(Denylist::class), $claims)
            : $claims;
    }

    /**
     * A new outbound HTTP request already carrying a fresh service token.
     */
    public function request(?string $audience = null): PendingRequest
    {
        return Http::withToken($this->issue($audience)->token);
    }

    /**
     * Attach a fresh service token to an existing outbound request.
     */
    public function authenticate(PendingRequest $request, ?string $audience = null): PendingRequest
    {
        return $request->withToken($this->issue($audience)->token);
    }

    /**
     * The verified claims of the service calling the current request, or null when
     * unauthenticated. With no guard, the first `service-jwt` guard that has a caller
     * wins; with a name, exactly that guard is asked (null when it is not a
     * `service-jwt` guard or has no caller).
     */
    public function claims(?string $guard = null): ?Claims
    {
        $serviceGuards = $this->serviceGuards();

        foreach ($guard === null ? $serviceGuards : [$guard] as $name) {
            if (! in_array($name, $serviceGuards, true)) {
                continue;
            }

            $instance = $this->container->make(AuthFactory::class)->guard($name);

            if ($instance instanceof ServiceGuard && $instance->user() !== null) {
                return $instance->payload();
            }
        }

        return null;
    }

    /**
     * Every configured guard using the `service-jwt` driver.
     *
     * @return list<string>
     */
    private function serviceGuards(): array
    {
        $guards = [];

        foreach ((array) $this->container->make(ConfigRepository::class)->get('auth.guards', []) as $name => $options) {
            if (is_string($name) && is_array($options) && ($options['driver'] ?? null) === 'service-jwt') {
                $guards[] = $name;
            }
        }

        return $guards;
    }
}
