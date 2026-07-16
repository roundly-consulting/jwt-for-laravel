<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use RoundlyConsulting\Jwt\UserTokens\TokenUser;

/**
 * What a host writes when it swaps `jwt.guard.identity`: the shipped identity
 * plus one extra behaviour. The seam is worthless unless the guard hands back
 * *this* class — not the packaged one it extends.
 */
class CustomIdentity extends TokenUser
{
    public function tenant(): string
    {
        return $this->claims()->has('tenant')
            ? $this->claims()->string('tenant')
            : 'none';
    }
}
