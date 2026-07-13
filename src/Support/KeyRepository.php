<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;

/**
 * Loads and caches the configured RSA keys from disk on first use.
 *
 * Verify-only applications configure a public key path only; issuers configure
 * both. Keys are parsed lazily so a misconfigured path fails at token time with
 * an actionable message rather than at boot. The PEM parsing and the key guards
 * (a real RSA key, at least 2048 bits, a sane exponent) are crypto-for-laravel's;
 * every failure is re-wrapped as {@see KeyLoadFailed} so hosts keep catching one
 * exception for "the configured JWT key is unusable".
 */
final class KeyRepository
{
    private ?RsaKey $privateKey = null;

    private ?RsaKey $publicKey = null;

    public function __construct(
        private readonly ?string $privateKeyPath,
        private readonly ?string $publicKeyPath,
    ) {}

    /**
     * @throws KeyLoadFailed
     */
    public function privateKey(): RsaKey
    {
        if ($this->privateKey instanceof RsaKey) {
            return $this->privateKey;
        }

        if ($this->privateKeyPath === null || $this->privateKeyPath === '') {
            throw KeyLoadFailed::privateKeyNotConfigured();
        }

        $pem = $this->read(
            $this->privateKeyPath,
            fn (): KeyLoadFailed => KeyLoadFailed::privateKeyMissing($this->privateKeyPath ?? ''),
        );

        try {
            return $this->privateKey = RsaKey::private($pem);
        } catch (CryptoException $e) {
            throw KeyLoadFailed::unusable('private', $e);
        }
    }

    /**
     * @throws KeyLoadFailed
     */
    public function publicKey(): RsaKey
    {
        if ($this->publicKey instanceof RsaKey) {
            return $this->publicKey;
        }

        if ($this->publicKeyPath === null || $this->publicKeyPath === '') {
            throw KeyLoadFailed::publicKeyNotConfigured();
        }

        $pem = $this->read(
            $this->publicKeyPath,
            fn (): KeyLoadFailed => KeyLoadFailed::publicKeyMissing($this->publicKeyPath ?? ''),
        );

        try {
            return $this->publicKey = RsaKey::public($pem);
        } catch (CryptoException $e) {
            throw KeyLoadFailed::unusable('public', $e);
        }
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
