<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Testing;

use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * A token minted or issued under {@see JwtFake}: the {@see IssuedToken} handed back,
 * and the claims it carries (read from its payload — every registered claim
 * included).
 */
final readonly class RecordedToken
{
    public function __construct(
        public IssuedToken $token,
        public Claims $claims,
    ) {}
}
