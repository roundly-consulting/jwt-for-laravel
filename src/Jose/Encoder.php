<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;

/**
 * Serialises a claim set into a compact JWS (`header.payload.signature`).
 *
 * The key type and the algorithm are checked against each other, so an RS256
 * token can only ever be produced with an RSA private key and an HS256 token
 * only with an HMAC secret.
 */
final class Encoder
{
    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws AlgorithmMismatch when the key type does not match the algorithm.
     */
    public function encode(array $claims, RsaPrivateKey|HmacSecret $key, Algorithm $alg, ?string $kid = null): string
    {
        $header = ['typ' => 'JWT', 'alg' => $alg->value];

        if ($kid !== null) {
            $header['kid'] = $kid;
        }

        $segments = [
            Base64Url::encode($this->json($header)),
            Base64Url::encode($this->json($claims)),
        ];

        $signature = $this->sign(implode('.', $segments), $key, $alg);

        $segments[] = Base64Url::encode($signature);

        return implode('.', $segments);
    }

    private function sign(string $input, RsaPrivateKey|HmacSecret $key, Algorithm $alg): string
    {
        if ($alg === Algorithm::RS256 && $key instanceof RsaPrivateKey) {
            return $this->signRsa($input, $key);
        }

        if ($alg === Algorithm::HS256 && $key instanceof HmacSecret) {
            return hash_hmac('sha256', $input, $key->value, true);
        }

        throw new AlgorithmMismatch("Key type is not valid for algorithm [{$alg->value}].");
    }

    private function signRsa(string $input, RsaPrivateKey $key): string
    {
        $signature = '';

        if (openssl_sign($input, $signature, $key->key, OPENSSL_ALGO_SHA256) === false) {
            self::drainOpenSslErrors();

            throw new MalformedToken('Failed to produce an RS256 signature.');
        }

        return $signature;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function json(array $data): string
    {
        // JSON_UNESCAPED_SLASHES keeps byte output identical to the reference
        // encoder so pre-captured parity fixtures reproduce exactly.
        return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function drainOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // Empty the queue so a later, unrelated call isn't blamed for it.
        }
    }
}
