<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Events;

use Carbon\CarbonImmutable;

/**
 * Dispatched after a user token (access / challenge / verify / custom) is minted.
 *
 * Carries only non-sensitive metadata — never the token string, the private key,
 * or any secret.
 */
final readonly class UserTokenIssued
{
    public function __construct(
        public string $subject,
        public string $scope,
        public string $jti,
        public CarbonImmutable $expiresAt,
    ) {}
}
