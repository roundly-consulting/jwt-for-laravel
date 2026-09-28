<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\Testing\RecordingServices;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

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
     * @param  array<string, mixed>  $claims
     *
     * @throws ServiceAuthMisconfigured
     */
    public function issue(?string $audience = null, array $claims = []): IssuedToken
    {
        return $this->container->make(ServiceTokenIssuer::class)->issue($audience, $claims);
    }

    /**
     * Verify an inbound service token addressed to this service.
     *
     * @throws JwtException|ServiceAuthMisconfigured
     */
    public function verify(string $jwt): Claims
    {
        return $this->container->make(ServiceTokenVerifier::class)->verify($jwt);
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
