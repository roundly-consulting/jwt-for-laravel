<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Jose\ClaimMismatchException;
use RoundlyConsulting\Crypto\Jose\Jws;
use RoundlyConsulting\Crypto\Jose\MalformedTokenException;
use RoundlyConsulting\Crypto\Jose\TokenExpiredException;
use RoundlyConsulting\Crypto\Jose\TokenNotYetValidException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\AlgorithmMismatchException;
use RoundlyConsulting\Crypto\Signature\Hs;
use RoundlyConsulting\Crypto\Signature\InvalidSignatureException;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Signature\Rs;
use RoundlyConsulting\Crypto\Signature\Verifier;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenNotYetValid;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedCriticalHeader;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedTokenType;

/**
 * Verifies a compact JWS and returns its {@see Claims} — the security-critical
 * heart of the package.
 *
 * The JWS structure, the strict algorithm pin and the signature check are done
 * by crypto-for-laravel's `Jws`; the temporal check by its opt-in
 * `Claims::assertTemporal()`. This class is the JWT boundary around them: it
 * enforces the two policies that are JWT-specific (RFC 8725 §3.11 explicit
 * typing, and outright `crit` rejection) and translates every crypto failure
 * into the package's own exception, so callers keep catching `MalformedToken`,
 * `AlgorithmMismatch`, `InvalidSignature`, `TokenExpired`, … exactly as before.
 *
 * A verifier is built with exactly one expected algorithm and a matching key
 * type. The header never selects the key or algorithm, so `alg:none` and
 * RS256↔HS256 confusion are structurally impossible.
 *
 * Validation order: key/alg pairing → length → structure → `crit` → `typ` →
 * alg pin → signature → `exp` → `nbf`/`iat`. Registered-claim pinning
 * (`iss`/`aud`), scope and denylist checks belong to the calling token service.
 */
final readonly class Decoder
{
    /**
     * Upper bound on a compact JWS we will even attempt to decode, mirrored from
     * the crypto package so callers (and the service-token verifier) can bound
     * bearer strings before any decode work.
     */
    public const int MAX_ENCODED_BYTES = Jws::MAX_ENCODED_BYTES;

    public function __construct(private Jws $jws = new Jws) {}

    /**
     * @throws AlgorithmMismatch|MalformedToken|InvalidSignature|TokenExpired|TokenNotYetValid|UnexpectedCriticalHeader|UnexpectedTokenType|ClaimMismatch
     */
    public function decode(string $jwt, RsaKey|HmacSecret $key, Algorithm $expected, int $leeway): Claims
    {
        $verifier = $this->verifier($key, $expected);

        $this->assertHeaderPolicy($jwt);

        try {
            $claims = $this->jws->verify($jwt, $verifier, $expected);
        } catch (AlgorithmMismatchException $e) {
            throw new AlgorithmMismatch('Token algorithm does not match the pinned algorithm.', previous: $e);
        } catch (InvalidSignatureException $e) {
            throw new InvalidSignature("{$expected->value} signature verification failed.", previous: $e);
        } catch (MalformedTokenException|InvalidEncodingException $e) {
            throw new MalformedToken($e->getMessage(), previous: $e);
        }

        try {
            $claims->assertTemporal($leeway);
        } catch (TokenExpiredException $e) {
            throw new TokenExpired('The token has expired.', previous: $e);
        } catch (TokenNotYetValidException $e) {
            throw new TokenNotYetValid($e->getMessage(), previous: $e);
        } catch (ClaimMismatchException $e) {
            // `exp` is mandatory: absent or non-integer is a claim error.
            throw new ClaimMismatch($e->getMessage(), previous: $e);
        }

        return new Claims($claims->all());
    }

    /**
     * The two JWT-specific header policies, checked before the signature so the
     * caller gets the precise reason. `crit` and a wrong `typ` are structural
     * rejections in this package, and crypto's `Jws` cannot distinguish them by
     * exception type (it reports both as a malformed token), so the header is
     * read here — the signature is still what makes the token trusted.
     *
     * @throws MalformedToken|UnexpectedCriticalHeader|UnexpectedTokenType
     */
    private function assertHeaderPolicy(string $jwt): void
    {
        if (strlen($jwt) > self::MAX_ENCODED_BYTES) {
            throw new MalformedToken('The token exceeds the maximum permitted length.');
        }

        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new MalformedToken('A compact JWS must have exactly three segments.');
        }

        $header = $this->decodeHeader($parts[0]);

        if (array_key_exists('crit', $header)) {
            throw new UnexpectedCriticalHeader('The `crit` header is not supported.');
        }

        $this->assertTokenType($header);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws MalformedToken
     */
    private function decodeHeader(string $segment): array
    {
        try {
            $decoded = json_decode(Base64Url::decode($segment), true, 512, JSON_THROW_ON_ERROR);
        } catch (InvalidEncodingException) {
            throw new MalformedToken('The token header is not valid base64url.');
        } catch (JsonException) {
            throw new MalformedToken('The token header is not valid JSON.');
        }

        if (! is_array($decoded) || (array_is_list($decoded) && $decoded !== [])) {
            throw new MalformedToken('The token header must be a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * RFC 8725 §3.11 explicit typing: when a `typ` header is present it must
     * identify a JWT, so an artifact signed with the same key but a different
     * media type can't be confused for one of our tokens. An absent `typ` is
     * accepted for interop (it is optional per RFC 7519). RFC 7519 permits
     * dropping the `application/` media-type prefix, so both forms are allowed.
     *
     * @param  array<string, mixed>  $header
     *
     * @throws UnexpectedTokenType
     */
    private function assertTokenType(array $header): void
    {
        if (! array_key_exists('typ', $header)) {
            return;
        }

        $typ = $header['typ'];
        $normalized = is_string($typ) ? strtolower($typ) : '';

        if ($normalized !== 'jwt' && $normalized !== 'application/jwt') {
            throw new UnexpectedTokenType('The token `typ` header must be "JWT" when present.');
        }
    }

    /**
     * @throws AlgorithmMismatch
     */
    private function verifier(RsaKey|HmacSecret $key, Algorithm $expected): Verifier
    {
        return match (true) {
            $expected === Algorithm::RS256 && $key instanceof RsaKey => new Rs($key),
            $expected === Algorithm::HS256 && $key instanceof HmacSecret => new Hs($key),
            default => throw new AlgorithmMismatch("Key type is not valid for algorithm [{$expected->value}]."),
        };
    }
}
