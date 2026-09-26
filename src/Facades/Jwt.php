<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Jwt\JwtManager;

/**
 * The one-call entry point to the package.
 *
 * @method static \RoundlyConsulting\Jwt\UserTokens\IssuedToken mintAccessToken(\RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest $request)
 * @method static \RoundlyConsulting\Jwt\UserTokens\IssuedToken mint(string $subject, string $scope, int $ttl, array<string, mixed> $extraClaims = [], string|null $audience = null)
 * @method static \RoundlyConsulting\Jwt\UserTokens\IssuedToken mintChallengeToken(string $subject, array<string, mixed> $extraClaims = [])
 * @method static \RoundlyConsulting\Jwt\UserTokens\IssuedToken mintEmailVerifyToken(string $subject, string $email)
 * @method static \RoundlyConsulting\Jwt\Jose\Claims verify(string $jwt, string|null $audience = null)
 * @method static \RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService service()
 * @method static \RoundlyConsulting\Jwt\ServiceTokens\ServiceCaller caller()
 * @method static \RoundlyConsulting\Jwt\Denylist\Contracts\Denylist denylist()
 * @method static void logout(\RoundlyConsulting\Jwt\UserTokens\IssuedToken $token)
 * @method static void denyClaims(\RoundlyConsulting\Jwt\Jose\Claims $claims)
 * @method static \RoundlyConsulting\Jwt\Jose\Claims|null claims(string|null $guard = null)
 * @method static string audienceFor(string $guard)
 * @method static \RoundlyConsulting\Jwt\UserTokens\JwtGuardSettings guardSettings(string $guard)
 *
 * @see JwtManager
 */
final class Jwt extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return JwtManager::class;
    }
}
