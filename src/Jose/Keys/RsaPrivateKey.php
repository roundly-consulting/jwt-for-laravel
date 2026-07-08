<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Keys;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;

/**
 * A validated RSA private key used to sign RS256 tokens.
 *
 * Only issuer applications hold one. Construction proves the PEM is a real RSA
 * key of at least 2048 bits.
 */
final readonly class RsaPrivateKey
{
    private function __construct(public OpenSSLAsymmetricKey $key) {}

    /**
     * @throws KeyLoadFailed
     */
    public static function fromPem(#[\SensitiveParameter] string $pem): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            throw KeyLoadFailed::unreadable('private', '<pem>');
        }

        RsaKeyGuard::assertRsaAtLeast2048($key, 'private');

        return new self($key);
    }
}
