<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Contracts;

use RoundlyConsulting\Jwt\Jose\Claims;
use SensitiveParameter;

interface ServiceTokenVerifier
{
    /**
     * Verify an HS256 service token addressed to this service and return its
     * claims.
     */
    public function verify(#[SensitiveParameter] string $jwt): Claims;
}
