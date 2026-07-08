<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use Carbon\CarbonImmutable;
use JsonException;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenNotYetValid;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedCriticalHeader;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;

/**
 * Verifies a compact JWS and returns its {@see Claims} — the security-critical
 * heart of the package.
 *
 * A verifier is built with exactly one expected algorithm and a matching key
 * type. The header's `alg` must string-equal the expectation; the header never
 * selects the key or algorithm, so `alg:none` and RS256↔HS256 confusion are
 * structurally impossible. A `crit` header is rejected outright.
 *
 * Validation order: signature → `exp` → `nbf`/`iat`. Registered-claim pinning
 * (`iss`/`aud`), scope and denylist checks belong to the calling token service.
 */
final class Decoder
{
    /**
     * @throws AlgorithmMismatch|MalformedToken|InvalidSignature|TokenExpired|TokenNotYetValid|UnexpectedCriticalHeader
     */
    public function decode(string $jwt, RsaPublicKey|HmacSecret $key, Algorithm $expected, int $leeway): Claims
    {
        $this->assertKeyMatchesAlgorithm($key, $expected);

        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new MalformedToken('A compact JWS must have exactly three segments.');
        }

        [$headerSegment, $payloadSegment, $signatureSegment] = $parts;

        $header = $this->decodeJsonObject(Base64Url::decode($headerSegment), 'header');

        if (array_key_exists('crit', $header)) {
            throw new UnexpectedCriticalHeader('The `crit` header is not supported.');
        }

        $alg = $header['alg'] ?? null;

        // Pin the algorithm before decoding the signature so an `alg:none`
        // downgrade (typically an empty signature segment) is rejected here.
        // Strict string equality — never a case-insensitive or type-juggling
        // compare — so `none`/`None`/`NONE` and any mismatched alg are rejected.
        if (! is_string($alg) || $alg !== $expected->value) {
            throw new AlgorithmMismatch('Token algorithm does not match the pinned algorithm.');
        }

        $payload = $this->decodeJsonObject(Base64Url::decode($payloadSegment), 'payload');
        $signature = Base64Url::decode($signatureSegment);

        $this->verifySignature($headerSegment.'.'.$payloadSegment, $signature, $key, $expected);

        $claims = new Claims($payload);

        $this->assertTemporal($claims, $leeway);

        return $claims;
    }

    private function assertKeyMatchesAlgorithm(RsaPublicKey|HmacSecret $key, Algorithm $expected): void
    {
        $matches = match ($expected) {
            Algorithm::RS256 => $key instanceof RsaPublicKey,
            Algorithm::HS256 => $key instanceof HmacSecret,
        };

        if (! $matches) {
            throw new AlgorithmMismatch("Key type is not valid for algorithm [{$expected->value}].");
        }
    }

    private function verifySignature(string $input, string $signature, RsaPublicKey|HmacSecret $key, Algorithm $expected): void
    {
        match ($expected) {
            Algorithm::RS256 => $this->verifyRsa($input, $signature, $key),
            Algorithm::HS256 => $this->verifyHmac($input, $signature, $key),
        };
    }

    private function verifyRsa(string $input, string $signature, RsaPublicKey|HmacSecret $key): void
    {
        // $key is always RsaPublicKey here (guarded above); the union satisfies
        // the match arm's signature.
        if (! $key instanceof RsaPublicKey) {
            throw new AlgorithmMismatch('RS256 requires an RSA public key.');
        }

        $result = openssl_verify($input, $signature, $key->key, OPENSSL_ALGO_SHA256);

        if ($result === 1) {
            return;
        }

        if ($result === -1) {
            // Drain the OpenSSL error queue so a later call isn't misattributed.
            while (openssl_error_string() !== false) {
            }
        }

        throw new InvalidSignature('RS256 signature verification failed.');
    }

    private function verifyHmac(string $input, string $signature, RsaPublicKey|HmacSecret $key): void
    {
        if (! $key instanceof HmacSecret) {
            throw new AlgorithmMismatch('HS256 requires an HMAC secret.');
        }

        $expected = hash_hmac('sha256', $input, $key->value, true);

        // Constant-time comparison defeats signature-timing side channels.
        if (! hash_equals($expected, $signature)) {
            throw new InvalidSignature('HS256 signature verification failed.');
        }
    }

    private function assertTemporal(Claims $claims, int $leeway): void
    {
        $now = CarbonImmutable::now()->getTimestamp();

        // `exp` is mandatory; a missing or non-integer value throws ClaimMismatch.
        $exp = $claims->int('exp');

        if ($now - $leeway >= $exp) {
            throw new TokenExpired('The token has expired.');
        }

        if ($claims->has('nbf')) {
            if ($claims->int('nbf') > $now + $leeway) {
                throw new TokenNotYetValid('The token is not valid yet (nbf).');
            }
        }

        if ($claims->has('iat')) {
            if ($claims->int('iat') > $now + $leeway) {
                throw new TokenNotYetValid('The token was issued in the future (iat).');
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonObject(string $json, string $part): array
    {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new MalformedToken("The token {$part} is not valid JSON.");
        }

        if (! is_array($decoded) || (array_is_list($decoded) && $decoded !== [])) {
            throw new MalformedToken("The token {$part} must be a JSON object.");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
