<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens\Contracts;

use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

interface UserTokenIssuer
{
    /**
     * Mint a signed RS256 user token for the given subject and scope.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(string $subject, string $scope, int $ttl, array $extraClaims = []): IssuedToken;
}
