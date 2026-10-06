<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Jose\Jwk;
use RoundlyConsulting\Crypto\Signature\Algorithm;
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

    /**
     * @param  string|null  $kid  the `jwt.kid` minted into token headers, published in {@see jwks()}
     */
    public function __construct(
        private readonly ?string $privateKeyPath,
        private readonly ?string $publicKeyPath,
        private readonly ?string $kid = null,
    ) {}

    /**
     * A repository over an already-loaded key pair, with no files behind it —
     * what `Jwt::fake()` installs so tests mint and verify without key files. The
     * public half is derived from the private key.
     *
     * @throws KeyLoadFailed when the key is not a private key.
     */
    public static function inMemory(RsaKey $privateKey, ?string $kid = null): self
    {
        if (! $privateKey->isPrivate) {
            throw KeyLoadFailed::privateKeyNotConfigured();
        }

        $repository = new self(null, null, $kid);

        try {
            $repository->privateKey = $privateKey;
            $repository->publicKey = RsaKey::public($privateKey->publicPem());
        } catch (CryptoException $e) {
            throw KeyLoadFailed::unusable('public', $e);
        }

        return $repository;
    }

    /**
     * The RFC 7517 JWK Set publishing the public key: `kty`, `n`, `e`, `alg`
     * (RS256), `use` (sig) and — when configured — the `kid` minted into token
     * headers, so a verifier can match a token to its key.
     *
     * @return array{keys: list<array<string, string>>}
     *
     * @throws KeyLoadFailed
     */
    public function jwks(): array
    {
        try {
            $jwk = Jwk::fromPublicKey($this->publicKey())
                ->withAlg(Algorithm::RS256)
                ->withUse('sig')
                ->withKid($this->kid === '' ? null : $this->kid);
        } catch (CryptoException $e) {
            throw KeyLoadFailed::unusable('public', $e);
        }

        return ['keys' => [$jwk->toArray()]];
    }

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
            'private',
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
            'public',
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
    private function read(string $kind, string $path, callable $missing): string
    {
        if (! is_file($path)) {
            throw $missing();
        }

        if (! is_readable($path)) {
            throw KeyLoadFailed::unreadable($kind, $path);
        }

        // `@`: a file that turns unreadable between the check and the read would
        // raise a warning, which Laravel's error handler turns into an
        // ErrorException instead of this package's KeyLoadFailed.
        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw KeyLoadFailed::unreadable($kind, $path);
        }

        return $contents;
    }
}
