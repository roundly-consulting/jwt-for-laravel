<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/**
 * Verifies RS256 user tokens offline with the configured public key, strictly
 * pinning the issuer and audience.
 *
 * Algorithm is pinned to RS256 by the {@see Decoder}; this layer adds the
 * `iss`/`aud` equality checks. Scope, denylist and token-version enforcement
 * live in the guard, not here.
 */
final class NativeUserTokenVerifier implements UserTokenVerifier
{
    public function __construct(
        private readonly Decoder $decoder,
        private readonly KeyRepository $keys,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly int $leeway,
    ) {}

    public function verify(string $jwt): Claims
    {
        $claims = $this->decoder->decode($jwt, $this->keys->publicKey(), Algorithm::RS256, $this->leeway);

        if ($claims->require('iss') !== $this->issuer) {
            throw new ClaimMismatch('Token issuer does not match the expected issuer.');
        }

        if ($claims->require('aud') !== $this->audience) {
            throw new ClaimMismatch('Token audience does not match the expected audience.');
        }

        return $claims;
    }
}
