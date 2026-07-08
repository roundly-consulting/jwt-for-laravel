<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Enums\Helpers;

/**
 * The JWS signature algorithms this package supports.
 *
 * Deliberately limited to one asymmetric (RS256, user tokens) and one
 * symmetric (HS256, service tokens) algorithm — every verifier is pinned to
 * exactly one case, which is what makes algorithm-confusion impossible.
 */
enum Algorithm: string
{
    use Helpers;

    case RS256 = 'RS256';
    case HS256 = 'HS256';

    /**
     * Whether the algorithm uses a public/private keypair (RSA) rather than a
     * shared secret.
     */
    public function isAsymmetric(): bool
    {
        return $this === self::RS256;
    }
}
