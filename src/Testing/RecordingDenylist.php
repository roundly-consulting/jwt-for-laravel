<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Testing;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * The `denylist()` sub-accessor under `Jwt::fake()`: wraps the bound denylist, so
 * every deny still lands in the real store (and `has()` answers from it), and
 * records the denied `jti` — including denies made through `logout()` and
 * `denyClaims()`.
 */
final readonly class RecordingDenylist implements Denylist
{
    public function __construct(
        private JwtFake $fake,
        private Denylist $inner,
    ) {}

    public function has(string $jti): bool
    {
        return $this->inner->has($jti);
    }

    public function deny(string $jti, CarbonImmutable $until): void
    {
        $this->inner->deny($jti, $until);

        $this->fake->recordDenied($jti);
    }

    public function denyToken(IssuedToken $token): void
    {
        $this->inner->denyToken($token);

        $this->fake->recordDenied($token->jti);
    }
}
