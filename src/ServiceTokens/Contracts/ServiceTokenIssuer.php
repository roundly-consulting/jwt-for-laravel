<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Contracts;

use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

interface ServiceTokenIssuer
{
    /**
     * Issue an HS256 service token for the given audience (defaults to the
     * configured service audience).
     */
    public function issue(?string $audience = null): IssuedToken;
}
