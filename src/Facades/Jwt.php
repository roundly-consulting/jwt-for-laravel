<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Facades;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\JwtManager;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\Testing\JwtFake;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\GuardTokens;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\Scope;

/**
 * The one-call entry point to the package.
 *
 * @method static IssuedToken mintAccessToken(AccessTokenRequest $request)
 * @method static IssuedToken mint(string $subject, Scope|string $scope, int $ttl, array<string, mixed> $extraClaims = [], ?string $audience = null)
 * @method static IssuedToken mintChallengeToken(string $subject, array<string, mixed> $extraClaims = [])
 * @method static IssuedToken mintEmailVerifyToken(string $subject, string $email)
 * @method static Claims verify(string $jwt, ?string $audience = null)
 * @method static GuardTokens guard(string $name)
 * @method static Services services()
 * @method static Denylist denylist()
 * @method static void logout(IssuedToken $token)
 * @method static void denyClaims(Claims $claims)
 * @method static RsaKey publicKey()
 * @method static array{keys: list<array<string, string>>} jwks()
 *
 * @see JwtManager
 */
final class Jwt extends Facade
{
    /**
     * Swap the manager for a recording fake over in-memory RSA keys. Tokens are still
     * really signed and verified; every mint, service-token issue and deny is
     * recorded, and `actingAs()` authenticates a guard for the rest of the test.
     */
    public static function fake(): JwtFake
    {
        $fake = new JwtFake(self::getFacadeApplication() ?? Container::getInstance());

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return JwtManager::class;
    }
}
