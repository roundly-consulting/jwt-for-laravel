<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Denylist\Contracts;

use Carbon\CarbonImmutable;

/**
 * A store of revoked token ids (`jti`) — used to log a user out before their
 * token naturally expires.
 */
interface Denylist
{
    public function has(string $jti): bool;

    /**
     * Deny a token id until the given instant (typically its `exp`).
     */
    public function deny(string $jti, CarbonImmutable $until): void;
}
