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
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Jwt\Console\GenerateKeysCommand;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ChecksPermissions;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

final class JwtServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/jwt.php', 'jwt');

        $this->app->singleton(Encoder::class);
        $this->app->singleton(Decoder::class);

        $this->app->singleton(KeyRepository::class, fn (): KeyRepository => new KeyRepository(
            $this->nullableString(config('jwt.private_key_path')),
            $this->nullableString(config('jwt.public_key_path')),
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
        ));

        $this->app->bind(ServiceTokenIssuer::class, NativeServiceTokenService::class);
        $this->app->bind(ServiceTokenVerifier::class, NativeServiceTokenService::class);

        $this->app->singleton(Denylist::class, fn (Application $app): CacheDenylist => new CacheDenylist(
            $app->make(CacheFactory::class),
            $this->nullableString(config('jwt.denylist.store')),
            (string) config('jwt.denylist.prefix'),
            $this->dispatcher($app),
        ));

        $this->app->singleton(JwtManager::class, fn (Application $app): JwtManager => new JwtManager($app));
    }

    public function boot(): void
    {
        $this->registerUserGuard();
        $this->registerServiceGuard();
        $this->registerClaimAuthorization();

        if ($this->app->runningInConsole()) {
            $this->commands([GenerateKeysCommand::class]);

            $this->publishes([
                __DIR__.'/../config/jwt.php' => config_path('jwt.php'),
            ], 'jwt-config');
        }
    }

    private function registerUserGuard(): void
    {
        // The AuthManager rebinds the extend closure's scope when it invokes it,
        // so `$this`/`self::` are unavailable here — everything is resolved from
        // `$app`, config and imported class names inline.
        Auth::extend('jwt', static function (Application $app, string $name, array $config): JwtGuard {
            $provider = null;

            if (isset($config['provider']) && is_string($config['provider'])) {
                /** @var AuthManager $auth */
                $auth = $app->make('auth');
                $provider = $auth->createUserProvider($config['provider']);
            }

            $identity = config('jwt.guard.identity');
            $identityClass = is_string($identity) && is_subclass_of($identity, ClaimsAuthenticatable::class)
                ? $identity
                : TokenUser::class;

            $configured = config('jwt.guard.token_version');
            $tokenVersion = null;

            if ($configured instanceof Closure) {
                $tokenVersion = static fn (Authenticatable $user): int => (int) $configured($user);
            } elseif (is_string($configured) && class_exists($configured)) {
                $instance = $app->make($configured);

                if (is_callable($instance)) {
                    $tokenVersion = static fn (Authenticatable $user): int => (int) $instance($user);
                }
            }

            $guard = new JwtGuard(
                $app->make(UserTokenVerifier::class),
                $app->make(Denylist::class),
                $app->make('request'),
                (string) config('jwt.guard.scope'),
                $identityClass,
                (bool) config('jwt.guard.check_denylist'),
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
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }
}
