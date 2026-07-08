<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Keys;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;

/**
 * Shared RSA key validation: asserts a loaded OpenSSL key really is RSA and at
 * least 2048 bits, draining the OpenSSL error queue on failure.
 *
 * @internal
 */
final class RsaKeyGuard
{
    private const MIN_BITS = 2048;

    /**
     * @throws KeyLoadFailed
     */
    public static function assertRsaAtLeast2048(OpenSSLAsymmetricKey $key, string $kind): void
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw KeyLoadFailed::unreadable($kind, '<pem>');
        }

        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw KeyLoadFailed::notRsa($kind);
        }

        $bits = (int) ($details['bits'] ?? 0);

        if ($bits < self::MIN_BITS) {
            throw KeyLoadFailed::tooSmall($kind, $bits);
        }
    }
}
