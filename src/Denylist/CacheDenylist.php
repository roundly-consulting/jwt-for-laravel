<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Denylist;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Events\TokenDenied;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * A cache-backed denylist. Each denied `jti` is stored under a prefixed key
 * with a TTL equal to the token's remaining verifiable lifetime — its `exp`
 * plus the verifier's clock-skew leeway — so entries evict exactly when the
 * token could no longer verify anyway: no unbounded growth, and no window in
 * which a denied token outlives its denial.
 */
final class CacheDenylist implements Denylist
{
    /**
     * @param  int  $leeway  the verifier's clock-skew leeway (`jwt.leeway`): a token
     *                       still verifies until `exp + leeway`, so its denial must last as long
     */
    public function __construct(
        private readonly CacheFactory $cache,
        private readonly ?string $store,
        private readonly string $prefix,
        private readonly ?Dispatcher $events = null,
        private readonly int $leeway = 0,
    ) {}

    public function has(string $jti): bool
    {
        return $this->cache->store($this->store)->has($this->key($jti));
    }

    public function deny(string $jti, CarbonImmutable $until): void
    {
        $seconds = $until->getTimestamp() + max(0, $this->leeway) - CarbonImmutable::now()->getTimestamp();

        // Nothing to do for a token past `exp + leeway`; it can no longer verify.
        if ($seconds <= 0) {
            return;
        }

        $this->cache->store($this->store)->put($this->key($jti), true, $seconds);

        $this->events?->dispatch(new TokenDenied($jti, $until));
    }

    public function denyToken(IssuedToken $token): void
    {
        $this->deny($token->jti, $token->expiresAt);
    }

    private function key(string $jti): string
    {
        return $this->prefix.$jti;
    }
}
