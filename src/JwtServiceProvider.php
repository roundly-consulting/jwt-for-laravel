<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use RoundlyConsulting\Jwt\Console\GenerateKeysCommand;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\Support\KeyPath;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ChecksPermissions;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenVerifier;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;

final class JwtServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('jwt')
            ->hasConfigFile()
            ->hasCommands([GenerateKeysCommand::class])
            ->contributesToAbout(static fn (): array => [
                // Booleans and algorithm names only — never key material, a
                // secret, or a path that would point at one.
                'User tokens' => 'RS256',
                'Signing key' => self::configured('jwt.private_key_path'),
                'Verification key' => self::configured('jwt.public_key_path'),
                'Issuer' => self::configured('jwt.issuer'),
                'Audience' => self::configured('jwt.audience'),
                'Access token TTL' => self::seconds('jwt.ttl'),
                'Service tokens' => self::serviceTokenMode(),
                'Denylist check' => (bool) config('jwt.guard.check_denylist') ? 'ON' : 'OFF',
                'Claim authorization' => (bool) config('jwt.authorize_from_claims') ? 'ON' : 'OFF',
            ]);
    }

    public function register(): void
    {
        parent::register();

        $this->app->singleton(Encoder::class);
        $this->app->singleton(Decoder::class);

        $this->app->singleton(KeyRepository::class, fn (): KeyRepository => new KeyRepository(
            $this->resolvedKeyPath(config('jwt.private_key_path')),
            $this->resolvedKeyPath(config('jwt.public_key_path')),
        ));

        $this->app->singleton(UserTokenIssuer::class, fn (Application $app): NativeUserTokenIssuer => new NativeUserTokenIssuer(
            $app->make(Encoder::class),
            $app->make(KeyRepository::class),
            (string) config('jwt.issuer'),
            (string) config('jwt.audience'),
            (int) config('jwt.ttl'),
            (int) config('jwt.challenge_ttl'),
            (int) config('jwt.verify_ttl'),
            $this->nullableString(config('jwt.kid')),
            $this->dispatcher($app),
        ));

        $this->app->singleton(UserTokenVerifier::class, fn (Application $app): NativeUserTokenVerifier => new NativeUserTokenVerifier(
            $app->make(Decoder::class),
            $app->make(KeyRepository::class),
            (string) config('jwt.issuer'),
            (string) config('jwt.audience'),
            (int) config('jwt.leeway'),
        ));

        $this->app->singleton(NativeServiceTokenService::class, fn (Application $app): NativeServiceTokenService => new NativeServiceTokenService(
            $app->make(Encoder::class),
            $app->make(Decoder::class),
            $this->nullableString(config('jwt.service.secret')),
            (string) config('jwt.service.issuer'),
            $this->nullableString(config('jwt.service.audience')),
            (int) config('jwt.service.ttl'),
            $this->stringList(config('jwt.service.issuers')),
            (string) config('app.service'),
            (int) config('jwt.leeway'),
            $this->dispatcher($app),
            $this->secretMap(config('jwt.service.secrets')),
        ));

        $this->app->bind(ServiceTokenIssuer::class, NativeServiceTokenService::class);
        $this->app->bind(ServiceTokenVerifier::class, NativeServiceTokenService::class);

        $this->app->singleton(Denylist::class, fn (Application $app): CacheDenylist => new CacheDenylist(
            $app->make(CacheFactory::class),
            $this->nullableString(config('jwt.denylist.store')),
            (string) config('jwt.denylist.prefix'),
            $this->dispatcher($app),
            (int) config('jwt.leeway'),
        ));

        $this->app->singleton(JwtManager::class, fn (Application $app): JwtManager => new JwtManager($app));
    }

    public function boot(): void
    {
        parent::boot();

        $this->registerUserGuard();
        $this->registerServiceGuard();
        $this->registerClaimAuthorization();
    }

    /**
     * Whether a config key holds a non-empty string, without ever echoing the
     * value itself (keys, secrets and key paths are all sensitive here).
     */
    private static function configured(string $key): string
    {
        $value = config($key);

        return is_string($value) && trim($value) !== '' ? 'SET' : 'MISSING';
    }

    private static function seconds(string $key): string
    {
        $value = config($key);

        return is_numeric($value) ? ((int) $value).'s' : 'DEFAULT';
    }

    /**
     * The HS256 keying mode a host has actually configured: per-issuer secrets
     * override the single shared secret, and neither one means service tokens
     * cannot be issued or verified at all.
     */
    private static function serviceTokenMode(): string
    {
        if (self::configured('jwt.service.secrets') === 'SET') {
            return 'HS256 (per-issuer secrets)';
        }

        if (self::configured('jwt.service.secret') === 'SET') {
            return 'HS256 (shared secret)';
        }

        return 'HS256 (no secret)';
    }

    private function registerUserGuard(): void
    {
        // The AuthManager rebinds the extend closure's scope when it invokes it,
        // so `$this`/`self::` are unavailable here — everything is resolved from
        // `$app`, config and imported class names inline.
        Auth::extend('jwt', static function (Application $app, string $name, array $config): JwtGuard {
            // One resolution path for every per-guard option (and its global
            // fallback) — the same one Jwt::guardSettings() hands consumers.
            $settings = $app->make(JwtManager::class)->guardSettings($name);

            $provider = null;

            if (isset($config['provider']) && is_string($config['provider'])) {
                /** @var AuthManager $auth */
                $auth = $app->make('auth');
                $provider = $auth->createUserProvider($config['provider']);
            }

            $configured = $settings->tokenVersion;
            $tokenVersion = null;

            if ($configured instanceof Closure) {
                $tokenVersion = static fn (Authenticatable $user): int => (int) $configured($user);
            } elseif (is_string($configured)) {
                // Fail closed: a class-string that is missing or not invokable must not
                // quietly disable the freshness check (a bumped version would then
                // revoke nothing) — surface it as the operator error it is.
                $instance = class_exists($configured) ? $app->make($configured) : null;

                if (! is_callable($instance)) {
                    throw JwtMisconfigured::invalidTokenVersion($name);
                }

                $tokenVersion = static fn (Authenticatable $user): int => (int) $instance($user);
            }

            $guard = new JwtGuard(
                $app->make(UserTokenVerifier::class),
                $app->make(Denylist::class),
                $app->make('request'),
                $settings->audience,
                $settings->scope,
                $settings->identity,
                $settings->checkDenylist,
                $tokenVersion,
                $provider,
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    private function registerServiceGuard(): void
    {
        Auth::extend('service-jwt', static function (Application $app): ServiceGuard {
            $guard = new ServiceGuard(
                $app->make(ServiceTokenVerifier::class),
                $app->make('request'),
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    private function registerClaimAuthorization(): void
    {
        if ((bool) config('jwt.authorize_from_claims') !== true) {
            return;
        }

        // Return null (not false) on a miss so other gate checks still run.
        Gate::before(static function (?Authenticatable $user, string $ability): ?bool {
            if ($user instanceof ChecksPermissions && $user->hasPermission($ability)) {
                return true;
            }

            return null;
        });
    }

    private function dispatcher(Application $app): ?Dispatcher
    {
        return $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null;
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * A configured key path, anchored to the application root when relative, so
     * key loading never depends on the process's working directory.
     */
    private function resolvedKeyPath(mixed $value): ?string
    {
        $path = $this->nullableString($value);

        return $path === null ? null : KeyPath::resolve($path, $this->app->basePath());
    }

    /**
     * Parses the `SERVICE_JWT_SECRETS` per-issuer map: a comma-separated list
     * of `issuer:secret` pairs. Malformed pairs are dropped rather than half-
     * parsed into a wrong issuer→secret binding.
     *
     * @return array<string, string>
     */
    private function secretMap(mixed $value): array
    {
        if (! is_string($value) || trim($value) === '') {
            return [];
        }

        $map = [];

        foreach (explode(',', $value) as $pair) {
            $pair = trim($pair);

            if ($pair === '' || ! str_contains($pair, ':')) {
                continue;
            }

            [$issuer, $secret] = explode(':', $pair, 2);

            // Trim both sides so `billing: s3cret` doesn't derive a different
            // HMAC key from a stray space, and a padded issuer still matches.
            $issuer = trim($issuer);
            $secret = trim($secret);

            if ($issuer !== '' && $secret !== '') {
                $map[$issuer] = $secret;
            }
        }

        return $map;
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $item) {
            // Trim so `JWT_SERVICE_ISSUERS="billing, api"` doesn't yield a
            // never-matching " api" entry; drop blanks.
            if (is_string($item) && ($trimmed = trim($item)) !== '') {
                $strings[] = $trimmed;
            }
        }

        return $strings;
    }
}
