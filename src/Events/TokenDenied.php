<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Events;

use Carbon\CarbonImmutable;

/**
 * Dispatched when a token id (`jti`) is added to the denylist (a logout / revoke).
 */
final readonly class TokenDenied
{
    public function __construct(
        public string $jti,
        public CarbonImmutable $until,
    ) {}
}
