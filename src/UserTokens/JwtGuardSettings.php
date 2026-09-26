<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Closure;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\UserTokens\Contracts\ClaimsAuthenticatable;

/**
 * The effective options of one `jwt` guard: its own `auth.guards.<name>` keys,
 * each falling back to the global `jwt.*` value.
 *
 * Resolved in exactly one place ({@see JwtManager::guardSettings()}) and used
 * both to build the guard and by anything that has to reason about it, so the
 * guard and its consumers can never disagree about the fallback chain.
 */
final readonly class JwtGuardSettings
{
    /**
     * @param  class-string<ClaimsAuthenticatable>  $identity
     * @param  string|Closure|null  $tokenVersion  exactly what is configured: an invokable class-string, a closure, or null
     */
    public function __construct(
        public string $guard,
        public string $audience,
        public string $scope,
        public bool $checkDenylist,
        public string $identity,
        public string|Closure|null $tokenVersion,
    ) {}
}
