<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use RoundlyConsulting\Jwt\Console\GenerateKeysCommand;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\Support\KeyPath;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\Support\Settings;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ChecksPermissions;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenVerifier;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\PackageToolkit\Support\Config;

final class JwtServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $app = $this->app;

        $package
            ->name('jwt')
            ->hasConfigFile()
            ->hasCommands([GenerateKeysCommand::class])
            ->contributesToAbout(static fn (): array => [
                // Booleans and algorithm names only — never key material, a
                // secret, or a path that would point at one.
                'User tokens' => 'RS256',
                'Signing key' => self::keyFile('jwt.private_key_path', $app->basePath()),
                'Verification key' => self::keyFile('jwt.public_key_path', $app->basePath()),
                'Issuer' => self::configured('jwt.issuer'),
                'Audience' => self::configured('jwt.audience'),
                'Access token TTL' => self::seconds('jwt.ttl', 900),
                'Service tokens' => self::serviceTokenMode(),
                'Denylist check' => Config::using(JwtMisconfigured::class)->boolean('jwt.guard.check_denylist', true) ? 'ON' : 'OFF',
                'Claim authorization' => Config::using(JwtMisconfigured::class)->boolean('jwt.authorize_from_claims') ? 'ON' : 'OFF',
            ]);
    }

    public function register(): void
    {
        parent::register();

        $this->app->singleton(Encoder::class);
        $this->app->singleton(Decoder::class);

        $this->app->singleton(KeyRepository::class, fn (): KeyRepository => new KeyRepository(
            $this->resolvedKeyPath(Settings::optionalString('jwt.private_key_path', config('jwt.private_key_path'))),
            $this->resolvedKeyPath(Settings::optionalString('jwt.public_key_path', config('jwt.public_key_path'))),
            Settings::optionalString('jwt.kid', config('jwt.kid')),
        ));

        // An absent issuer/audience stays '' here so minting and verifying throw the
        // dedicated missingIssuer()/missingAudience(); a non-string one throws now.
        $this->app->singleton(UserTokenIssuer::class, fn (Application $app): NativeUserTokenIssuer => new NativeUserTokenIssuer(
            $app->make(Encoder::class),
            $app->make(KeyRepository::class),
            Settings::optionalString('jwt.issuer', config('jwt.issuer')) ?? '',
            Settings::optionalString('jwt.audience', config('jwt.audience')) ?? '',
            Settings::integer('jwt.ttl', config('jwt.ttl'), 900, min: 1),
            Settings::integer('jwt.challenge_ttl', config('jwt.challenge_ttl'), 300, min: 1),
            Settings::integer('jwt.verify_ttl', config('jwt.verify_ttl'), 3600, min: 1),
            Settings::optionalString('jwt.kid', config('jwt.kid')),
            $this->dispatcher($app),
        ));

        $this->app->singleton(UserTokenVerifier::class, fn (Application $app): NativeUserTokenVerifier => new NativeUserTokenVerifier(
            $app->make(Decoder::class),
            $app->make(KeyRepository::class),
            Settings::optionalString('jwt.issuer', config('jwt.issuer')) ?? '',
            Settings::optionalString('jwt.audience', config('jwt.audience')) ?? '',
            Settings::integer('jwt.leeway', config('jwt.leeway'), 10, min: 0),
        ));

        $this->app->singleton(NativeServiceTokenService::class, function (Application $app): NativeServiceTokenService {
            $serviceName = $this->serviceName();

            return new NativeServiceTokenService(
                $app->make(Encoder::class),
                $app->make(Decoder::class),
                Settings::optionalString('jwt.service.secret', config('jwt.service.secret')),
                Settings::optionalString('jwt.service.issuer', config('jwt.service.issuer')) ?? $serviceName,
                Settings::optionalString('jwt.service.audience', config('jwt.service.audience')),
                Settings::integer('jwt.service.ttl', config('jwt.service.ttl'), 60, min: 1),
                Settings::stringList('jwt.service.issuers', config('jwt.service.issuers')),
                $serviceName,
                Settings::integer('jwt.leeway', config('jwt.leeway'), 10, min: 0),
                $this->dispatcher($app),
                $this->secretMap(config('jwt.service.secrets')),
            );
        });

        $this->app->bind(ServiceTokenIssuer::class, NativeServiceTokenService::class);
        $this->app->bind(ServiceTokenVerifier::class, NativeServiceTokenService::class);

        $this->app->singleton(Denylist::class, fn (Application $app): CacheDenylist => new CacheDenylist(
            $app->make(CacheFactory::class),
            Settings::optionalString('jwt.denylist.store', config('jwt.denylist.store')),
            Settings::string('jwt.denylist.prefix', config('jwt.denylist.prefix'), 'jwt:denylist:'),
            $this->dispatcher($app),
            Settings::integer('jwt.leeway', config('jwt.leeway'), 10, min: 0),
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

    /**
     * Whether a configured key path points at a readable file — both paths have
     * defaults, so "configured" alone would always read SET. The path itself is
     * never echoed.
     */
    private static function keyFile(string $key, string $basePath): string
    {
        $path = config($key);

        if (! is_string($path) || trim($path) === '') {
            return 'MISSING';
        }

        $path = KeyPath::resolve($path, $basePath);

        return is_file($path) && is_readable($path) ? 'SET' : 'MISSING';
    }

    /**
     * A TTL through its strict reader — `INVALID` rather than a throw, so `about`
     * reports a misconfiguration instead of dying on it (the real reads still throw).
     */
    private static function seconds(string $key, int $default): string
    {
        try {
            return Settings::integer($key, config($key), $default, min: 1).'s';
        } catch (JwtMisconfigured) {
            return 'INVALID';
        }
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
            // fallback) — the same one Jwt::guard($name)->settings() hands consumers.
            $settings = $app->make(JwtManager::class)->guard($name)->settings();

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
        // Strict: `JWT_AUTHORIZE_FROM_CLAIMS=disabled` fails the boot rather than reading as off.
        if (! Config::using(JwtMisconfigured::class)->boolean('jwt.authorize_from_claims')) {
            return;
        }

        $app = $this->app;

        // Return null (not false) on a miss so other gate checks still run.
        Gate::before(static function (?Authenticatable $user, string $ability) use ($app): ?bool {
            if ($user instanceof ChecksPermissions) {
                return $user->hasPermission($ability) ? true : null;
            }

            return $user !== null && self::tokenPermits($app, $user, $ability) ? true : null;
        });
    }

    /**
     * Provider mode: an Eloquent user carries no permissions of its own, so read
     * the `permissions` claim of the token that authenticated it on the request's
     * active guard (the one `auth:<guard>` selected). Only for that exact user
     * instance — never another model loaded for the same key — and a mistyped
     * claim grants nothing.
     */
    private static function tokenPermits(Application $app, Authenticatable $user, string $ability): bool
    {
        $guard = $app->make(AuthFactory::class)->guard();

        if (! $guard instanceof JwtGuard || $guard->user() !== $user) {
            return false;
        }

        $claims = $guard->payload();

        try {
            return $claims !== null
                && $claims->has('permissions')
                && in_array($ability, $claims->list('permissions'), true);
        } catch (ClaimMismatch) {
            return false;
        }
    }

    private function dispatcher(Application $app): ?Dispatcher
    {
        return $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null;
    }

    /**
     * This service's own name — the `aud` inbound service tokens must carry, and
     * the default `iss` of the ones it mints: `jwt.service.name`, else a host's
     * `app.service` (not a stock Laravel key, but services that define it keep
     * their identity), else a slug of `app.name`. '' when none can be derived, so
     * verification fails closed instead of pinning nothing. A `jwt.service.name`
     * that is not a string throws rather than silently re-pinning to `app.name`.
     */
    private function serviceName(): string
    {
        foreach ([Settings::optionalString('jwt.service.name', config('jwt.service.name')), config('app.service')] as $value) {
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        $appName = config('app.name');

        return is_string($appName) ? Str::slug($appName) : '';
    }

    /**
     * A configured key path, anchored to the application root when relative, so
     * key loading never depends on the process's working directory.
     */
    private function resolvedKeyPath(?string $path): ?string
    {
        return $path === null ? null : KeyPath::resolve($path, $this->app->basePath());
    }

    /**
     * Parses the `SERVICE_JWT_SECRETS` per-issuer map: a comma-separated list
     * of `issuer:secret` pairs (null or blank = per-issuer mode off). A malformed
     * pair throws rather than being dropped: dropping every pair would quietly
     * fall back to the shared `secret`, unbinding each issuer from its own key.
     *
     * @return array<string, string>
     *
     * @throws JwtMisconfigured
     */
    private function secretMap(mixed $value): array
    {
        $value = Settings::optionalString('jwt.service.secrets', $value);

        if ($value === null) {
            return [];
        }

        $map = [];

        foreach (explode(',', $value) as $pair) {
            // Trim both sides so `billing: s3cret` doesn't derive a different
            // HMAC key from a stray space, and a padded issuer still matches.
            [$issuer, $secret] = str_contains($pair, ':') ? array_map(trim(...), explode(':', $pair, 2)) : ['', ''];

            if ($issuer === '' || $secret === '') {
                throw JwtMisconfigured::malformedSecretPair();
            }

            $map[$issuer] = $secret;
        }

        return $map;
    }
}
