<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Denylist\Contracts;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

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

    /**
     * Deny a freshly issued token until its own expiry (one-call logout).
     */
    public function denyToken(IssuedToken $token): void;
}
