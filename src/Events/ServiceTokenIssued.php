<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Events;

use Carbon\CarbonImmutable;

/**
 * Dispatched after an HS256 service token is issued.
 *
 * Carries only non-sensitive metadata — never the token string or shared secret.
 * `$subject` is the token's `sub` when it was issued with one, else null.
 */
final readonly class ServiceTokenIssued
{
    public function __construct(
        public string $issuer,
        public ?string $audience,
        public string $jti,
        public CarbonImmutable $expiresAt,
        public ?string $subject = null,
    ) {}
}
