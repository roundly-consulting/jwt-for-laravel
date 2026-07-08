<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use RoundlyConsulting\Jwt\Jose\Claims;

/**
 * An authenticatable identity that can be built directly from verified token
 * claims — the claims-mode counterpart to an Eloquent user provider.
 */
interface ClaimsAuthenticatable extends Authenticatable
{
    public static function fromClaims(Claims $claims): self;
}
