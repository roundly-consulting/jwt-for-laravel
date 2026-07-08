<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

use RoundlyConsulting\Jwt\Jose\Claims;

interface UserTokenVerifier
{
    /**
     * Verify an RS256 user token (signature, expiry, pinned iss/aud) and return
     * its claims.
     */
    public function verify(string $jwt): Claims;
}
