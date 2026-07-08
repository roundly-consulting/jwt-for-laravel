<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Denylist;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;

/**
 * A cache-backed denylist. Each denied `jti` is stored under a prefixed key
 * with a TTL equal to the token's remaining lifetime, so entries evict exactly
 * when the token would have expired anyway — no unbounded growth.
 */
final class CacheDenylist implements Denylist
{
    public function __construct(
        private readonly CacheFactory $cache,
        private readonly ?string $store,
        private readonly string $prefix,
    ) {}

    public function has(string $jti): bool
    {
        return $this->cache->store($this->store)->has($this->key($jti));
    }

    public function deny(string $jti, CarbonImmutable $until): void
    {
        $seconds = $until->getTimestamp() - CarbonImmutable::now()->getTimestamp();

        // Nothing to do for an already-expired token; it can no longer verify.
        if ($seconds <= 0) {
            return;
        }

        $this->cache->store($this->store)->put($this->key($jti), true, $seconds);
    }

    private function key(string $jti): string
    {
        return $this->prefix.$jti;
    }
}
