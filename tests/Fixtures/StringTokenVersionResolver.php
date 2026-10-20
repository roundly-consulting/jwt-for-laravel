<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * An invokable `token_version` resolver that breaks its contract: it returns a
 * version tag string, not an int.
 */
final class StringTokenVersionResolver
{
    public function __invoke(Authenticatable $user): string
    {
        return 'v3';
    }
}
