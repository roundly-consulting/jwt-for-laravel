<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
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
        private readonly ?string $kid = null,
    ) {}

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

        return new IssuedToken($token, $expiresAt, $jti);
    }

    /**
     * Convenience wrapper preserving the platform's access-token shape.
     *
     * @param  list<string>  $permissions
     */
    public function mintAccessToken(
        string $subject,
        string $email,
        bool $emailVerified,
        int $tokenVersion,
        array $permissions = [],
    ): IssuedToken {
        return $this->mint($subject, 'access', $this->ttl, [
            'email' => $email,
            'email_verified' => $emailVerified,
            'tv' => $tokenVersion,
            'permissions' => $permissions,
        ]);
    }
}
