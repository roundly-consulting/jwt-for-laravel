<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

/**
 * An identity that can answer whether it holds a given permission, sourced from
 * its token claims. Consulted by the optional claim-based `Gate::before` hook.
 */
interface ChecksPermissions
{
    public function hasPermission(string $ability): bool;
}
