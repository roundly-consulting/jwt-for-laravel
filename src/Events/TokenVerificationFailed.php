<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Events;

/**
 * Dispatched when an explicit token verification fails.
 *
 * Carries the failure reason and the exception class only — never the raw token,
 * a secret, or a key. Fired from the explicit verify path (the `Jwt` facade), not
 * the guard's silent per-request resolution, to avoid an event per anonymous probe.
 */
final readonly class TokenVerificationFailed
{
    /**
     * @param  class-string  $exceptionClass
     */
    public function __construct(
        public string $reason,
        public string $exceptionClass,
    ) {}
}
