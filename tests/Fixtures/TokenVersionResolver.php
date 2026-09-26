<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * An invokable `token_version` resolver — the config-cache-safe shape (a
 * class-string survives `config:cache`; a closure does not).
 */
final class TokenVersionResolver
{
    public function __invoke(Authenticatable $user): int
    {
        return 7;
    }
}
