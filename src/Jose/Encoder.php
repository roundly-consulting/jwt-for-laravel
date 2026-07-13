<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\Signer;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnencodableClaims;

/**
 * Serialises a claim set into a compact JWS (`header.payload.signature`).
 *
 * The JWS serialisation and the signature math live in crypto-for-laravel; this
 * class is the package boundary. It pairs the key with the algorithm — so an
 * RS256 token can only ever be produced with an RSA private key and an HS256
 * token only with an HMAC secret — pins the package to its two supported
 * algorithms, and re-wraps every crypto failure as the JWT exception callers
 * already catch.
 */
final readonly class Encoder
{
    public function __construct(private Jws $jws = new Jws) {}

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws AlgorithmMismatch when the key type does not match the algorithm.
     * @throws UnencodableClaims when a claim value cannot be encoded to JSON.
     * @throws MalformedToken when the signature cannot be produced.
     */
    public function encode(array $claims, RsaKey|HmacSecret $key, Algorithm $alg, ?string $kid = null): string
    {
        $signer = $this->signer($key, $alg);

        try {
            return $this->jws->sign($kid === null ? [] : ['kid' => $kid], $claims, $signer);
        } catch (CryptoException $e) {
            // A claim carrying non-UTF-8 bytes surfaces as a malformed token from
            // crypto; anything else here is a signing failure (a public key, or
            // OpenSSL itself). Either way it stays inside this package's contract.
            throw $e instanceof MalformedTokenException
                ? new UnencodableClaims('A claim value could not be encoded to JSON.', previous: $e)
                : new MalformedToken("Failed to produce a {$alg->value} signature.", previous: $e);
        }
    }

    /**
     * @throws AlgorithmMismatch
     */
    private function signer(RsaKey|HmacSecret $key, Algorithm $alg): Signer
    {
        return match (true) {
            $alg === Algorithm::RS256 && $key instanceof RsaKey => new Rs($key),
            $alg === Algorithm::HS256 && $key instanceof HmacSecret => new Hs($key),
            default => throw new AlgorithmMismatch("Key type is not valid for algorithm [{$alg->value}]."),
        };
    }
}
