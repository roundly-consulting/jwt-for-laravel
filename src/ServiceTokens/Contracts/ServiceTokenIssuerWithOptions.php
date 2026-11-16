<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Contracts;

use DateInterval;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * A {@see ServiceTokenIssuer} that also takes per-call options: a token lifetime and
 * a subject. `Jwt::services()->issue(ttl: …, subject: …)` requires the bound issuer
 * to implement this and refuses one that does not — a plain issuer would silently
 * drop the options and mint a token that lives longer, or names no one.
 *
 * Separate from {@see ServiceTokenIssuer} only so a host implementation of that
 * contract keeps compiling in 2.x; the two merge in 3.0.
 */
interface ServiceTokenIssuerWithOptions extends ServiceTokenIssuer
{
    /**
     * `$ttl` overrides `jwt.service.ttl` for this token: whole seconds (an int, or a
     * `DateInterval` / `CarbonInterval` with no fractional seconds), at least 1 and at
     * most `jwt.service.max_ttl`. `$subject` becomes the `sub` claim — the only way a
     * service token carries one (a `sub` in `$claims` is still refused).
     *
     * @param  array<string, mixed>  $claims  additional, non-registered claims
     *
     * @throws ServiceAuthMisconfigured for an out-of-bounds ttl or an invalid subject.
     */
    public function issue(
        ?string $audience = null,
        array $claims = [],
        int|DateInterval|null $ttl = null,
        ?string $subject = null,
    ): IssuedToken;
}
