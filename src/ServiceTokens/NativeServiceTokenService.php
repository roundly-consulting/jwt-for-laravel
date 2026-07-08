<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * Mints and verifies HS256 machine-to-machine service tokens.
 *
 * Every token is pinned to `scope=service` and HS256. Verification requires the
 * audience to equal this service's own name, a non-empty issuer, and — when an
 * allow-list is configured — an issuer within it. A missing shared secret is a
 * misconfiguration ({@see ServiceAuthMisconfigured}, → 500), never a rejected
 * caller (401).
 */
final class NativeServiceTokenService implements ServiceTokenIssuer, ServiceTokenVerifier
{
    private const SCOPE = 'service';

    /**
     * @param  list<string>  $allowedIssuers  empty ⇒ any issuer accepted
     */
    public function __construct(
        private readonly Encoder $encoder,
        private readonly Decoder $decoder,
        #[\SensitiveParameter] private readonly ?string $secret,
        private readonly string $issuer,
        private readonly ?string $defaultAudience,
        private readonly int $ttl,
        private readonly array $allowedIssuers,
        private readonly string $serviceName,
        private readonly int $leeway,
    ) {}

    public function issue(?string $audience = null): IssuedToken
    {
        $secret = $this->secret();

        $now = CarbonImmutable::now();
        $expiresAt = $now->addSeconds($this->ttl);
        $jti = (string) Str::uuid();

        $claims = [
            'iss' => $this->issuer,
            'aud' => $audience ?? $this->defaultAudience,
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $expiresAt->getTimestamp(),
            'jti' => $jti,
            'scope' => self::SCOPE,
        ];

        $token = $this->encoder->encode($claims, $secret, Algorithm::HS256);

        return new IssuedToken($token, $expiresAt, $jti);
    }

    public function verify(string $jwt): Claims
    {
        $claims = $this->decoder->decode($jwt, $this->secret(), Algorithm::HS256, $this->leeway);

        if ($claims->get('scope') !== self::SCOPE) {
            throw new ClaimMismatch('Service token scope is not "service".');
        }

        if ($claims->get('aud') !== $this->serviceName) {
            throw new ClaimMismatch('Service token audience does not match this service.');
        }

        $issuer = $claims->get('iss');

        if (! is_string($issuer) || $issuer === '') {
            throw new ClaimMismatch('Service token issuer is missing.');
        }

        if ($this->allowedIssuers !== [] && ! in_array($issuer, $this->allowedIssuers, true)) {
            throw new ClaimMismatch('Service token issuer is not allow-listed.');
        }

        return $claims;
    }

    /**
     * @throws ServiceAuthMisconfigured
     */
    private function secret(): HmacSecret
    {
        if ($this->secret === null || $this->secret === '') {
            throw ServiceAuthMisconfigured::missingSecret();
        }

        return new HmacSecret($this->secret);
    }
}
