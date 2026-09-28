<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Testing;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Factory;

/**
 * A cache factory with one private in-memory store, whatever store name is
 * asked for — what the denylist runs on under `Jwt::fake()`, so a test never
 * needs the cache server `jwt.denylist.store` points at.
 *
 * @internal
 */
final class InMemoryCache implements Factory
{
    private readonly Repository $store;

    public function __construct()
    {
        $this->store = new Repository(new ArrayStore);
    }

    public function store($name = null): Repository
    {
        return $this->store;
    }
}
