<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Events\TokenVerificationFailed;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceCaller;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\JwtGuardSettings;
use RoundlyConsulting\Jwt\UserTokens\Scope;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

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
     * Pass a {@see Scope} case for a built-in scope, or any string for a custom one.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, Scope|string $scope, int $ttl, array $extraClaims = [], ?string $audience = null): IssuedToken
    {
        return $this->issuer()->mint($subject, $scope, $ttl, $extraClaims, $audience);
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
     * resolution does not emit the event. `$audience` pins a specific audience
     * (e.g. `audienceFor('clients')`); null keeps the configured `jwt.audience`.
     *
     * @throws JwtException
     */
    public function verify(string $jwt, ?string $audience = null): Claims
    {
        try {
            return $this->verifier()->verify($jwt, $audience);
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
     * With no guard, the first `jwt` guard that has a user wins; with a guard
     * name, exactly that guard is asked (null when it is not a `jwt` guard or
     * has no user). Resolved through the auth manager's per-request guard(s) —
     * never static state — so long-lived workers (Octane, queues) can't leak
     * one request's claims into the next.
     */
    public function claims(?string $guard = null): ?Claims
    {
        $jwtGuards = $this->jwtGuards($this->container->make(ConfigRepository::class));

        foreach ($guard === null ? array_keys($jwtGuards) : [$guard] as $name) {
            if (! array_key_exists($name, $jwtGuards)) {
                continue;
            }

            $instance = $this->container->make(AuthFactory::class)->guard($name);

            if ($instance instanceof JwtGuard && $instance->user() !== null) {
                return $instance->payload();
            }
        }

        return null;
    }

    /**
     * The audience tokens for this guard are minted for and verified against:
     * `auth.guards.<guard>.audience` when set, else `jwt.audience`.
     *
     * @throws JwtMisconfigured when the guard is not a `jwt` guard.
     */
    public function audienceFor(string $guard): string
    {
        return $this->guardSettings($guard)->audience;
    }

    /**
     * The effective options of a `jwt` guard — each `auth.guards.<guard>` key
     * (`audience`, `scope`, `check_denylist`, `identity`, `token_version`)
     * falling back to its global `jwt.*` counterpart. The `jwt` guard driver is
     * built from exactly this, so what a consumer reads here is what the guard
     * enforces.
     *
     * @throws JwtMisconfigured when the guard is not a `jwt` guard.
     */
    public function guardSettings(string $guard): JwtGuardSettings
    {
        return $this->resolveGuardSettings($guard, $this->container->make(ConfigRepository::class));
    }

    private function issuer(): UserTokenIssuer
    {
        return $this->container->make(UserTokenIssuer::class);
    }

    private function verifier(): UserTokenVerifier
    {
        return $this->container->make(UserTokenVerifier::class);
    }

    private function resolveGuardSettings(string $guard, ConfigRepository $config): JwtGuardSettings
    {
        $options = $this->jwtGuards($config)[$guard] ?? throw JwtMisconfigured::notAJwtGuard($guard);

        return new JwtGuardSettings(
            guard: $guard,
            audience: $this->nonEmptyString($options['audience'] ?? null) ?? (string) $config->get('jwt.audience'),
            scope: $this->scope($options['scope'] ?? null) ?? $this->globalScope($config->get('jwt.guard.scope')),
            checkDenylist: $this->bool($options['check_denylist'] ?? null) ?? (bool) $config->get('jwt.guard.check_denylist'),
            identity: $this->identityClass($options['identity'] ?? null)
                ?? $this->identityClass($config->get('jwt.guard.identity'))
                ?? TokenUser::class,
            tokenVersion: $this->tokenVersion($options['token_version'] ?? null)
                ?? $this->tokenVersion($config->get('jwt.guard.token_version')),
        );
    }

    /**
     * Every configured guard using the `jwt` driver, keyed by guard name.
     *
     * @return array<string, array<string, mixed>>
     */
    private function jwtGuards(ConfigRepository $config): array
    {
        $guards = [];

        foreach ((array) $config->get('auth.guards', []) as $name => $options) {
            if (is_string($name) && is_array($options) && ($options['driver'] ?? null) === 'jwt') {
                /** @var array<string, mixed> $options */
                $guards[$name] = $options;
            }
        }

        return $guards;
    }

    /**
     * A per-guard scope: a {@see Scope} case normalised to its wire value, or a
     * plain string as-is. Anything else defers to the global scope.
     */
    private function scope(mixed $value): ?string
    {
        return match (true) {
            $value instanceof Scope => $value->value,
            is_string($value) => $value,
            default => null,
        };
    }

    private function globalScope(mixed $value): string
    {
        return $value instanceof Scope ? $value->value : (string) $value;
    }

    private function nonEmptyString(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? $value : null;
    }

    /**
     * A per-guard boolean, tolerating env-style strings ("false", "0") that a
     * plain `(bool)` cast would read as true.
     */
    private function bool(mixed $value): ?bool
    {
        return $value === null ? null : filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
    }

    /**
     * @return class-string<ClaimsAuthenticatable>|null
     */
    private function identityClass(mixed $value): ?string
    {
        return is_string($value) && is_subclass_of($value, ClaimsAuthenticatable::class) ? $value : null;
    }

    private function tokenVersion(mixed $value): string|Closure|null
    {
        return $value instanceof Closure ? $value : $this->nonEmptyString($value);
    }

    private function events(): ?Dispatcher
    {
        return $this->container->bound(Dispatcher::class)
            ? $this->container->make(Dispatcher::class)
            : null;
    }
}
