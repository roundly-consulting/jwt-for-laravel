<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Keys;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;

/**
 * A validated RSA public key used to verify RS256 signatures.
 *
 * Construction proves the PEM is a real RSA key of at least 2048 bits, so the
 * verifier can never be handed a non-RSA or undersized key — this typing is
 * part of what blocks algorithm confusion.
 */
final readonly class RsaPublicKey
{
    private function __construct(public OpenSSLAsymmetricKey $key) {}

    /**
     * @throws KeyLoadFailed
     */
    public static function fromPem(#[\SensitiveParameter] string $pem): self
    {
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw KeyLoadFailed::unreadable('public', '<pem>');
        }

        RsaKeyGuard::assertRsaAtLeast2048($key, 'public');

        return new self($key);
    }
}
