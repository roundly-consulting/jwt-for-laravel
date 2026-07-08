<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;

/**
 * Loads and caches the configured RSA keys from disk on first use.
 *
 * Verify-only applications configure a public key path only; issuers configure
 * both. Keys are parsed lazily so a misconfigured path fails at token time with
 * an actionable message rather than at boot.
 */
final class KeyRepository
{
    private ?RsaPrivateKey $privateKey = null;

    private ?RsaPublicKey $publicKey = null;

    public function __construct(
        private readonly ?string $privateKeyPath,
        private readonly ?string $publicKeyPath,
    ) {}

    /**
     * @throws KeyLoadFailed
     */
    public function privateKey(): RsaPrivateKey
    {
        if ($this->privateKey instanceof RsaPrivateKey) {
            return $this->privateKey;
        }

        if ($this->privateKeyPath === null || $this->privateKeyPath === '') {
            throw KeyLoadFailed::privateKeyNotConfigured();
        }

        return $this->privateKey = RsaPrivateKey::fromPem(
            $this->read($this->privateKeyPath, fn (): KeyLoadFailed => KeyLoadFailed::privateKeyMissing($this->privateKeyPath ?? '')),
        );
    }

    /**
     * @throws KeyLoadFailed
     */
    public function publicKey(): RsaPublicKey
    {
        if ($this->publicKey instanceof RsaPublicKey) {
            return $this->publicKey;
        }

        if ($this->publicKeyPath === null || $this->publicKeyPath === '') {
            throw KeyLoadFailed::publicKeyNotConfigured();
        }

        return $this->publicKey = RsaPublicKey::fromPem(
            $this->read($this->publicKeyPath, fn (): KeyLoadFailed => KeyLoadFailed::publicKeyMissing($this->publicKeyPath ?? '')),
        );
    }

    /**
     * @param  callable(): KeyLoadFailed  $missing
     *
     * @throws KeyLoadFailed
     */
    private function read(string $path, callable $missing): string
    {
        if (! is_file($path)) {
            throw $missing();
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw $missing();
        }

        return $contents;
    }
}
