<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use RoundlyConsulting\Jwt\Events\UserTokenIssued;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

/**
 * Mints RS256 user tokens signed with the configured RSA private key.
 *
 * Registered claims (`iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `scope`)
 * are authoritative and always overwrite any caller-supplied value of the same
 * name, so extra claims can never spoof the token's identity.
 */
final class NativeUserTokenIssuer implements UserTokenIssuer
{
    public function __construct(
        private readonly Encoder $encoder,
        private readonly KeyRepository $keys,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly int $ttl,
        private readonly int $challengeTtl,
        private readonly int $verifyTtl,
        private readonly ?string $kid = null,
        private readonly ?Dispatcher $events = null,
    ) {
        // Never mint a token with an empty identity pin — verifiers elsewhere
        // would be comparing against ''.
        if ($this->issuer === '') {
            throw JwtMisconfigured::missingIssuer();
        }

        if ($this->audience === '') {
            throw JwtMisconfigured::missingAudience();
        }
    }

    public function mint(string $subject, string $scope, int $ttl, array $extraClaims = []): IssuedToken
    {
        $now = CarbonImmutable::now();
        $expiresAt = $now->addSeconds($ttl);
        $jti = (string) Str::uuid();

        $claims = [
            ...$extraClaims,
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => $subject,
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $expiresAt->getTimestamp(),
            'jti' => $jti,
            'scope' => $scope,
        ];

        $token = $this->encoder->encode($claims, $this->keys->privateKey(), Algorithm::RS256, $this->kid);

        $this->events?->dispatch(new UserTokenIssued($subject, $scope, $jti, $expiresAt));

        return new IssuedToken($token, $expiresAt, $jti);
    }

    public function mintAccessToken(AccessTokenRequest $request): IssuedToken
    {
        return $this->mint($request->subject, Scopes::ACCESS, $this->ttl, $request->toClaims());
    }

    public function mintChallengeToken(string $subject, array $extraClaims = []): IssuedToken
    {
        return $this->mint($subject, Scopes::TWO_FA_PENDING, $this->challengeTtl, $extraClaims);
    }

    public function mintEmailVerifyToken(string $subject, string $email): IssuedToken
    {
        return $this->mint($subject, Scopes::EMAIL_VERIFY, $this->verifyTtl, ['email' => $email]);
    }
}
