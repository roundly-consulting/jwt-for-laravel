<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Denylist;

use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenRevoked;

/**
 * The one revocation check behind every `checkDenylist: true` verify and the
 * `service-jwt` guard's opt-in check, for user and service tokens alike.
 *
 * Fail closed: a token with no non-empty string `jti` can never be looked up, so it
 * could never be revoked — it is refused rather than waved through, exactly like
 * the `jwt` guard does.
 *
 * @internal
 */
final class RevocationCheck
{
    /**
     * @throws ClaimMismatch when the token carries no usable `jti`.
     * @throws TokenRevoked when its `jti` is denied.
     */
    public static function assertActive(Denylist $denylist, Claims $claims): Claims
    {
        $jti = $claims->get('jti');

        if (! is_string($jti) || $jti === '') {
            throw new ClaimMismatch('The token carries no jti, so its revocation cannot be checked.');
        }

        if ($denylist->has($jti)) {
            throw TokenRevoked::forJti($jti);
        }

        return $claims;
    }
}
