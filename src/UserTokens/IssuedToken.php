<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Carbon\CarbonImmutable;

/**
 * The result of minting a token: the compact JWS plus the metadata a caller
 * typically returns to the client (expiry) or records (jti, e.g. for denylist).
 */
final readonly class IssuedToken
{
    public function __construct(
        public string $token,
        public CarbonImmutable $expiresAt,
        public string $jti,
    ) {}
}
