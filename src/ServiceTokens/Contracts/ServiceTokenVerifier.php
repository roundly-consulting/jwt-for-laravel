<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Contracts;

use RoundlyConsulting\Jwt\Jose\Claims;

interface ServiceTokenVerifier
{
    /**
     * Verify an HS256 service token addressed to this service and return its
     * claims.
     */
    public function verify(string $jwt): Claims;
}
