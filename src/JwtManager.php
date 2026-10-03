<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Events\TokenVerificationFailed;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\Support\Settings;
use RoundlyConsulting\Jwt\Testing\JwtFake;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\GuardTokens;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\JwtGuardSettings;
use RoundlyConsulting\Jwt\UserTokens\Scope;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;
use RoundlyConsulting\PackageToolkit\Support\Config;

/**
 * The one obvious entry point behind the {@see Jwt} facade — inject it for the
 * facade-free form.
 *
 * A thin coordinator: every method delegates to a contract resolved lazily from
 * the container, so a verify-only app (no private key) can still resolve the
 * manager, and host overrides of any contract are always honoured. No token
 * logic lives here. Sub-areas hang off it: {@see guard()} (one `jwt` guard's
 * audience and claims), {@see Services()} (HS256 service tokens) and
 * {@see Denylist()}.
 *
 * Not final: {@see JwtFake} extends it, so code that injects the manager gets
 * the fake under `Jwt::fake()`.
 */
class JwtManager
{
    public function __construct(protected readonly Container $container) {}

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
     * resolution does not emit the event. `$audience` pins a specific audience;
     * null keeps the configured `jwt.audience`. To verify for a guard's audience
     * use `guard($name)->verify($jwt)`.
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

    /**
     * One `jwt` guard: mint and verify for its audience, read its settings and the
     * current request's claims on it.
     *
     * @throws JwtMisconfigured when the guard is not a `jwt` guard.
     */
    public function guard(string $name): GuardTokens
    {
        return new GuardTokens($this, $this->container, $this->resolveGuardSettings($name, $this->container->make(ConfigRepository::class)));
    }

    /**
     * HS256 machine-to-machine service tokens: issue, verify, attach to an
     * outbound request, and read the current request's calling service.
     */
    public function services(): Services
    {
        return new Services($this->container);
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
     * The RSA key user tokens are verified against — the configured
     * `jwt.public_key_path` — for hosts that publish it to other verifiers.
     *
     * @throws KeyLoadFailed when no usable public key is configured.
     */
    public function publicKey(): RsaKey
    {
        return $this->keys()->publicKey();
    }

    /**
     * The RFC 7517 JWK Set publishing {@see publicKey()} (`kty`, `n`, `e`, plus
     * `alg: RS256`, `use: sig` and the configured `jwt.kid`), ready to serve as
     * `/.well-known/jwks.json`.
     *
     * @return array{keys: list<array<string, string>>}
     *
     * @throws KeyLoadFailed when no usable public key is configured.
     */
    public function jwks(): array
    {
        return $this->keys()->jwks();
    }

    private function keys(): KeyRepository
    {
        return $this->container->make(KeyRepository::class);
    }

    private function issuer(): UserTokenIssuer
    {
        return $this->container->make(UserTokenIssuer::class);
    }

    private function verifier(): UserTokenVerifier
    {
        return $this->container->make(UserTokenVerifier::class);
    }

    /**
     * The effective options of a `jwt` guard — each `auth.guards.<guard>` key
     * (`audience`, `scope`, `check_denylist`, `identity`, `token_version`)
     * falling back to its global `jwt.*` counterpart. The `jwt` guard driver is
     * built from exactly this, so what a consumer reads is what the guard enforces.
     *
     * @throws JwtMisconfigured when the guard is not a `jwt` guard.
     */
    private function resolveGuardSettings(string $guard, ConfigRepository $config): JwtGuardSettings
    {
        $options = $this->jwtGuards($config)[$guard] ?? throw JwtMisconfigured::notAJwtGuard($guard);

        return new JwtGuardSettings(
            guard: $guard,
            audience: Settings::optionalString("auth.guards.{$guard}.audience", $options['audience'] ?? null)
                ?? Settings::optionalString('jwt.audience', $config->get('jwt.audience'))
                ?? '',
            scope: $this->scope("auth.guards.{$guard}.scope", $options['scope'] ?? null)
                ?? $this->scope('jwt.guard.scope', $config->get('jwt.guard.scope'))
                ?? Scope::Access->value,
            checkDenylist: $this->flag("auth.guards.{$guard}.check_denylist", $options['check_denylist'] ?? null)
                ?? $this->flag('jwt.guard.check_denylist', $config->get('jwt.guard.check_denylist'))
                ?? true,
            identity: $this->identityClass("auth.guards.{$guard}.identity", $options['identity'] ?? null)
                ?? $this->identityClass('jwt.guard.identity', $config->get('jwt.guard.identity'))
                ?? TokenUser::class,
            tokenVersion: $this->tokenVersion($options['token_version'] ?? null, $guard)
                ?? $this->tokenVersion($config->get('jwt.guard.token_version'), $guard),
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
     * A configured scope: a {@see Scope} case normalised to its wire value, or a
     * non-empty custom string as-is; null when not set — absent, null or blank —
     * (defer to the next level). Anything else throws — a mistyped scope must not
     * quietly defer to another.
     *
     * @throws JwtMisconfigured
     */
    private function scope(string $key, mixed $value): ?string
    {
        return match (true) {
            Settings::notSet($value) => null,
            $value instanceof Scope => $value->value,
            is_string($value) && trim($value) !== '' => $value,
            default => throw JwtMisconfigured::invalidValue($key, 'a Scope case or a non-empty string', $value),
        };
    }

    /**
     * A boolean switch: null when not set — absent, null or blank — (defer to the
     * next level, never a blank read as `false`), a bool for an env-style spelling
     * ("false", "0", "off" — a plain `(bool)` cast reads those as true), and a
     * {@see JwtMisconfigured} naming the key for anything else, so a typo never
     * quietly falls back to the global value.
     *
     * @throws JwtMisconfigured
     */
    private function flag(string $key, mixed $value): ?bool
    {
        return Settings::notSet($value) ? null : Config::for([$key => $value], JwtMisconfigured::class)->boolean($key);
    }

    /**
     * A configured claims-mode identity class, or null when not set — absent, null or
     * blank — (defer to the next level). Anything that is not a
     * {@see ClaimsAuthenticatable} class throws rather than silently becoming the
     * packaged {@see TokenUser}.
     *
     * @return class-string<ClaimsAuthenticatable>|null
     *
     * @throws JwtMisconfigured
     */
    private function identityClass(string $key, mixed $value): ?string
    {
        if (Settings::notSet($value)) {
            return null;
        }

        if (! is_string($value) || ! is_subclass_of($value, ClaimsAuthenticatable::class)) {
            throw JwtMisconfigured::invalidValue($key, 'a class implementing '.ClaimsAuthenticatable::class, $value);
        }

        return $value;
    }

    /**
     * A configured `token_version`: a closure or a class-string as-is, null when
     * unset or blank (defer to the global value). Anything else is refused rather
     * than read as "unset" — that would silently switch the freshness check off.
     *
     * @throws JwtMisconfigured
     */
    private function tokenVersion(mixed $value, string $guard): string|Closure|null
    {
        return match (true) {
            $value instanceof Closure => $value,
            Settings::notSet($value) => null,
            is_string($value) => $value,
            default => throw JwtMisconfigured::invalidTokenVersion($guard),
        };
    }

    private function events(): ?Dispatcher
    {
        return $this->container->bound(Dispatcher::class)
            ? $this->container->make(Dispatcher::class)
            : null;
    }
}
