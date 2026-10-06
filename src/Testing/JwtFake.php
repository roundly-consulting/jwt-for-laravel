<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Testing;

use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use InvalidArgumentException;
use PHPUnit\Framework\Assert;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Random\Token;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\Support\Settings;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\Scope;

/**
 * A recording, still-performing {@see JwtManager}, installed by `Jwt::fake()`.
 *
 * On construction it swaps the configured RSA keys for an **in-memory** key pair
 * (generated once per process), moves the package's cache denylist onto an
 * **in-memory** store (a host's own `Denylist` binding is left alone), fills an
 * empty `jwt.issuer` / `jwt.audience` / service secret with test values, and
 * drops every already-built issuer, verifier and guard so they pick the fakes
 * up — tests mint and verify without key files or a cache server. Tokens are then really signed and verified, and every mint, service-token
 * issue and deny is recorded for the `assert*()` helpers, whether it came through
 * the facade, an injected manager, `guard()`, `services()` or `denylist()`.
 *
 * `actingAs()` authenticates a `jwt` guard for the rest of the test without the
 * test building a token by hand.
 */
final class JwtFake extends JwtManager
{
    /** Registered claims `actingAs()` sets itself; the rest of its claims become extras. */
    private const array REGISTERED = ['iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti', 'scope'];

    private static ?RsaKey $keyPair = null;

    /** @var list<RecordedToken> */
    private array $minted = [];

    /** @var list<RecordedToken> */
    private array $serviceTokens = [];

    /** @var list<string> */
    private array $denied = [];

    private ?string $acting = null;

    /** @var list<string> bearer headers `actingAs()` attached, so a later call may replace them */
    private array $attached = [];

    private bool $listening = false;

    public function __construct(Container $container)
    {
        parent::__construct($container);

        $this->useInMemoryKeys();
    }

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, Scope|string $scope, int $ttl, array $extraClaims = [], ?string $audience = null): IssuedToken
    {
        return $this->recordMint(parent::mint($subject, $scope, $ttl, $extraClaims, $audience));
    }

    public function mintAccessToken(AccessTokenRequest $request): IssuedToken
    {
        return $this->recordMint(parent::mintAccessToken($request));
    }

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    public function mintChallengeToken(string $subject, array $extraClaims = []): IssuedToken
    {
        return $this->recordMint(parent::mintChallengeToken($subject, $extraClaims));
    }

    public function mintEmailVerifyToken(string $subject, string $email): IssuedToken
    {
        return $this->recordMint(parent::mintEmailVerifyToken($subject, $email));
    }

    public function services(): Services
    {
        return new RecordingServices($this, $this->container);
    }

    public function denylist(): Denylist
    {
        return new RecordingDenylist($this, parent::denylist());
    }

    /**
     * Authenticate the `jwt` guard as the given claims for the rest of the test: a
     * real token is minted for the guard's audience and scope (not recorded as a
     * mint) and sent as the bearer of the current and every later request that
     * carries no `Authorization` header of its own. `sub` is required; with an
     * Eloquent provider it must be a real user's key, and a guard with a
     * `token_version` needs a matching `tv`. Returns the token, e.g. for
     * `$this->withToken(...)`.
     *
     * @param  Claims|array<string, mixed>  $claims
     */
    public function actingAs(Claims|array $claims, string $guard): IssuedToken
    {
        $claims = $claims instanceof Claims ? $claims->all() : $claims;
        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) && ! is_int($subject)) {
            throw new InvalidArgumentException('Jwt::fake()->actingAs() needs a string or integer "sub" claim.');
        }

        $settings = $this->guard($guard)->settings();
        $scope = isset($claims['scope']) && is_string($claims['scope']) ? $claims['scope'] : $settings->scope;
        // The same strict read as the real issuer: an env string like '60' counts.
        $ttl = Settings::integer('jwt.ttl', $this->container->make(ConfigRepository::class)->get('jwt.ttl'), 900, min: 1);

        $token = $this->container->make(UserTokenIssuer::class)->mint(
            (string) $subject,
            $scope,
            $ttl,
            array_diff_key($claims, array_flip(self::REGISTERED)),
            $settings->audience,
        );

        $this->acting = $token->token;
        $this->attachActingToken();

        $auth = $this->container->make(AuthFactory::class);
        $auth->shouldUse($guard);

        // A user set earlier (Laravel's `actingAs($user, $guard)`) would otherwise
        // outrank the bearer this call attaches.
        $instance = $auth->guard($guard);

        if ($instance instanceof JwtGuard) {
            $instance->forgetUser();
        }

        return $token;
    }

    /**
     * @internal called by {@see RecordingServices}
     */
    public function recordServiceToken(IssuedToken $token): void
    {
        $this->serviceTokens[] = new RecordedToken($token, $this->claimsOf($token));
    }

    /**
     * @internal called by {@see RecordingDenylist}
     */
    public function recordDenied(string $jti): void
    {
        $this->denied[] = $jti;
    }

    /**
     * Every user token minted, in order.
     *
     * @return list<RecordedToken>
     */
    public function minted(): array
    {
        return $this->minted;
    }

    /**
     * Every service token issued, in order.
     *
     * @return list<RecordedToken>
     */
    public function serviceTokens(): array
    {
        return $this->serviceTokens;
    }

    /**
     * Every denied `jti`, in order.
     *
     * @return list<string>
     */
    public function denied(): array
    {
        return $this->denied;
    }

    /**
     * @param  (Closure(Claims): bool)|null  $where
     */
    public function assertMinted(?Closure $where = null): void
    {
        Assert::assertNotSame([], $this->matching($this->minted, $where), 'Expected a matching user token to be minted, but none was.');
    }

    public function assertNothingMinted(): void
    {
        $count = count($this->minted);

        Assert::assertSame(0, $count, "Expected no user token to be minted, but {$count} were.");
    }

    /**
     * @param  (Closure(Claims): bool)|null  $where
     */
    public function assertServiceTokenIssued(?string $audience = null, ?Closure $where = null): void
    {
        $matches = array_filter(
            $this->matching($this->serviceTokens, $where),
            static fn (RecordedToken $recorded): bool => $audience === null || $recorded->claims->get('aud') === $audience,
        );

        Assert::assertNotSame(
            [],
            $matches,
            'Expected a matching service token to be issued'.($audience === null ? '' : " for [{$audience}]").', but none was.',
        );
    }

    public function assertNothingIssuedToServices(): void
    {
        $count = count($this->serviceTokens);

        Assert::assertSame(0, $count, "Expected no service token to be issued, but {$count} were.");
    }

    public function assertDenied(?string $jti = null): void
    {
        Assert::assertTrue(
            $jti === null ? $this->denied !== [] : in_array($jti, $this->denied, true),
            'Expected '.($jti === null ? 'a token' : "token [{$jti}]").' to be denylisted, but it was not.',
        );
    }

    public function assertNothingDenied(): void
    {
        $count = count($this->denied);

        Assert::assertSame(0, $count, "Expected nothing to be denylisted, but {$count} token(s) were.");
    }

    private function recordMint(IssuedToken $token): IssuedToken
    {
        $this->minted[] = new RecordedToken($token, $this->claimsOf($token));

        return $token;
    }

    /**
     * @param  list<RecordedToken>  $recorded
     * @param  (Closure(Claims): bool)|null  $where
     * @return list<RecordedToken>
     */
    private function matching(array $recorded, ?Closure $where): array
    {
        return array_values(array_filter(
            $recorded,
            static fn (RecordedToken $token): bool => $where === null || $where($token->claims) === true,
        ));
    }

    /**
     * The payload of a token this fake just minted — read, not re-verified, so a
     * deliberately expired test token is recorded like any other.
     */
    private function claimsOf(IssuedToken $token): Claims
    {
        $payload = json_decode(Base64Url::decode(explode('.', $token->token)[1] ?? ''), true);

        /** @var array<string, mixed> $claims */
        $claims = is_array($payload) ? $payload : [];

        return new Claims($claims);
    }

    private function useInMemoryKeys(): void
    {
        $config = $this->container->make(ConfigRepository::class);

        foreach (['jwt.issuer' => 'jwt-fake-issuer', 'jwt.audience' => 'jwt-fake-audience'] as $key => $fallback) {
            if (! $this->filled($config->get($key))) {
                $config->set($key, $fallback);
            }
        }

        if (! $this->filled($config->get('jwt.service.secret')) && ! $this->filled($config->get('jwt.service.secrets'))) {
            $config->set('jwt.service.secret', Token::urlSafe(64));
        }

        $kid = $config->get('jwt.kid');

        $this->container->instance(KeyRepository::class, KeyRepository::inMemory(
            self::$keyPair ??= RsaKey::generate(2048),
            $this->filled($kid) && is_string($kid) ? $kid : null,
        ));

        $this->useInMemoryDenylist();

        if ($this->container instanceof IlluminateContainer) {
            foreach ([UserTokenIssuer::class, UserTokenVerifier::class, NativeServiceTokenService::class] as $abstract) {
                $this->container->forgetInstance($abstract);
            }
        }

        // Guards built before the swap hold the old verifier.
        $this->container->make(AuthManager::class)->forgetGuards();
    }

    /**
     * The guard checks the denylist on every request and `jwt.denylist.store`
     * defaults to `redis`, so the package's cache denylist moves onto a private
     * in-memory store — same prefix, leeway and `TokenDenied` event, no server.
     * Bound lazily, exactly like the provider's, so an `Event::fake()` made after
     * `Jwt::fake()` still sees the event. A host's own denylist is kept.
     */
    private function useInMemoryDenylist(): void
    {
        if (! $this->container->make(Denylist::class) instanceof CacheDenylist) {
            return;
        }

        $cache = new InMemoryCache;

        $this->container->singleton(Denylist::class, static function (Container $app) use ($cache): CacheDenylist {
            $config = $app->make(ConfigRepository::class);

            // Read exactly like the provider's binding: blank means the default.
            return new CacheDenylist(
                $cache,
                null,
                Settings::string('jwt.denylist.prefix', $config->get('jwt.denylist.prefix'), 'jwt:denylist:'),
                $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null,
                Settings::integer('jwt.leeway', $config->get('jwt.leeway'), 10, min: 0),
            );
        });
    }

    private function attachActingToken(): void
    {
        if ($this->container->bound('request')) {
            $this->withActingToken($this->container->make('request'));
        }

        if (! $this->listening && $this->container instanceof IlluminateContainer) {
            $this->listening = true;

            $this->container->rebinding('request', function (mixed $app, mixed $request): void {
                if ($request instanceof Request) {
                    $this->withActingToken($request);
                }
            });
        }
    }

    /**
     * An `Authorization` header the test set itself (`withToken()`) always wins.
     */
    private function withActingToken(Request $request): void
    {
        $current = $request->headers->get('Authorization');

        if ($this->acting === null || ($current !== null && ! in_array($current, $this->attached, true))) {
            return;
        }

        $bearer = 'Bearer '.$this->acting;
        $request->headers->set('Authorization', $bearer);
        $this->attached[] = $bearer;
    }

    private function filled(mixed $value): bool
    {
        return is_string($value) && trim($value) !== '';
    }
}
