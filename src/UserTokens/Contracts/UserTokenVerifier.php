<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

use RoundlyConsulting\Jwt\Jose\Claims;

interface UserTokenVerifier
{
    /**
     * Verify an RS256 user token (signature, expiry, pinned iss/aud) and return
     * its claims. `$audience` pins a specific audience for this call (null
     * keeps the configured `jwt.audience`; an empty string is a misconfiguration).
     */
    public function verify(string $jwt, ?string $audience = null): Claims;
}
