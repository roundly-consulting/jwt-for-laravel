<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Events\TokenVerificationFailed;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenRevoked;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/*
 * Revocation by `jti` for user AND service tokens: `verify(checkDenylist: true)` refuses
 * a revoked token, the plain `verify()` is unchanged, and `service-jwt` guards can opt in.
 */
const REVOCATION_SERVICE_SECRET = 'a-very-secret-service-key-0123456789';

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'jwt.service.secret' => REVOCATION_SERVICE_SECRET,
        'app.service' => 'opernity',
        'jwt.service.audience' => 'opernity',
        'auth.guards.users' => ['driver' => 'jwt', 'audience' => 'app-users'],
        'auth.guards.service' => ['driver' => 'service-jwt'],
    ]);

    Route::middleware('auth:service')->get('/internal', fn () => response()->json(['iss' => auth('service')->id()]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function serviceTokenWithout(string $claim): string
{
    $claims = [
        'iss' => 'opernity',
        'aud' => 'opernity',
        'iat' => 1_700_000_000,
        'exp' => 1_700_000_060,
        'jti' => 'jti-1',
        'scope' => 'service',
    ];
    unset($claims[$claim]);

    return (new Encoder)->encode($claims, HmacSecret::fromString(REVOCATION_SERVICE_SECRET), Algorithm::HS256);
}

describe('user tokens', function (): void {
    it('refuses a revoked token with checkDenylist and passes the plain verify', function (): void {
        $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));

        expect(Jwt::verify($issued->token, checkDenylist: true)->string('sub'))->toBe('user-1');

        Jwt::logout($issued);

        expect(Jwt::verify($issued->token)->string('sub'))->toBe('user-1')
            ->and(fn () => Jwt::verify($issued->token, checkDenylist: true))
            ->toThrow(function (TokenRevoked $e) use ($issued): void {
                expect($e)->toBeInstanceOf(JwtException::class)
                    ->and($e->jti())->toBe($issued->jti)
                    ->and($e::ERROR_CODE)->toBe('token_revoked')
                    ->and($e->getMessage())->toBe('The token has been revoked.');
            });
    });

    it('announces the refusal with TokenVerificationFailed', function (): void {
        Event::fake([TokenVerificationFailed::class]);

        $issued = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'));
        Jwt::denyClaims(Jwt::verify($issued->token));

        expect(fn () => Jwt::verify($issued->token, checkDenylist: true))->toThrow(TokenRevoked::class);

        Event::assertDispatched(TokenVerificationFailed::class, fn (TokenVerificationFailed $e): bool => $e->exceptionClass === TokenRevoked::class);
    });

    it('checks the denylist on one guard\'s verify', function (): void {
        $issued = Jwt::guard('users')->mintAccessToken(AccessTokenRequest::for('user-1'));
        Jwt::logout($issued);

        expect(Jwt::guard('users')->verify($issued->token)->string('aud'))->toBe('app-users')
            ->and(fn () => Jwt::guard('users')->verify($issued->token, checkDenylist: true))->toThrow(TokenRevoked::class);
    });

    it('refuses a token without jti when asked to check, failing closed', function (): void {
        $token = (new Encoder)->encode([
            'iss' => 'jwt-issuer',
            'aud' => 'web',
            'sub' => 'user-1',
            'exp' => 1_700_000_300,
            'scope' => 'access',
        ], rsaPrivateKey(), Algorithm::RS256);

        expect(Jwt::verify($token)->string('sub'))->toBe('user-1')
            ->and(fn () => Jwt::verify($token, checkDenylist: true))->toThrow(ClaimMismatch::class, 'no jti');
    });
});

describe('service tokens', function (): void {
    it('refuses a revoked token with checkDenylist and passes the plain verify', function (): void {
        $issued = Jwt::services()->issue(ttl: 300, subject: 'agent-run:1');

        expect(Jwt::services()->verify($issued->token, checkDenylist: true)->string('sub'))->toBe('agent-run:1');

        Jwt::logout($issued);

        expect(Jwt::services()->verify($issued->token)->string('jti'))->toBe($issued->jti)
            ->and(fn () => Jwt::services()->verify($issued->token, checkDenylist: true))
            ->toThrow(fn (TokenRevoked $e) => expect($e->jti())->toBe($issued->jti));
    });

    it('revokes from the verified claims as for a user token', function (): void {
        $issued = Jwt::services()->issue(ttl: 300);

        Jwt::denyClaims(Jwt::services()->verify($issued->token));

        expect(Jwt::denylist()->has($issued->jti))->toBeTrue()
            ->and(fn () => Jwt::services()->verify($issued->token, checkDenylist: true))->toThrow(TokenRevoked::class);
    });

    it('keeps the denial for the token\'s whole per-call lifetime', function (): void {
        config(['jwt.leeway' => 5]);
        app()->forgetInstance(Denylist::class);

        $issued = Jwt::services()->issue(ttl: 1800);
        Jwt::logout($issued);

        CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_001_799));

        expect(fn () => Jwt::services()->verify($issued->token, checkDenylist: true))->toThrow(TokenRevoked::class);
    });

    it('refuses a token without jti when asked to check, failing closed', function (): void {
        $token = serviceTokenWithout('jti');

        expect(Jwt::services()->verify($token)->string('iss'))->toBe('opernity')
            ->and(fn () => Jwt::services()->verify($token, checkDenylist: true))->toThrow(ClaimMismatch::class, 'no jti');
    });

    it('refuses a revoked token under Jwt::fake()', function (): void {
        $fake = Jwt::fake();

        $issued = Jwt::services()->issue(ttl: 60, subject: 'agent-run:1');
        Jwt::logout($issued);

        $fake->assertDenied($issued->jti);

        expect(Jwt::services()->verify($issued->token)->string('sub'))->toBe('agent-run:1')
            ->and(fn () => Jwt::services()->verify($issued->token, checkDenylist: true))->toThrow(TokenRevoked::class);
    });
});

describe('the service-jwt guard', function (): void {
    function revokedServiceToken(): IssuedToken
    {
        $issued = Jwt::services()->issue(ttl: 300);
        Jwt::logout($issued);

        return $issued;
    }

    it('does not check the denylist by default, as before', function (): void {
        $this->withToken(revokedServiceToken()->token)->getJson('/internal')->assertOk();

        expect(Auth::guard('service'))->toBeInstanceOf(ServiceGuard::class)
            ->and(Auth::guard('service')->checksDenylist())->toBeFalse();
    });

    it('never resolves the denylist while the check is off', function (): void {
        app()->singleton(Denylist::class, fn () => throw new RuntimeException('the denylist store is unreachable'));

        $token = Jwt::services()->issue()->token;

        $this->withToken($token)->getJson('/internal')->assertOk();
    });

    it('refuses a revoked token when jwt.service.check_denylist is on', function (mixed $flag): void {
        config(['jwt.service.check_denylist' => $flag]);

        $token = revokedServiceToken()->token;

        $this->withToken($token)->getJson('/internal')->assertUnauthorized();
        expect(Auth::guard('service')->validate(['token' => $token]))->toBeFalse();

        $this->withToken(Jwt::services()->issue()->token)->getJson('/internal')->assertOk()->assertExactJson(['iss' => 'opernity']);
    })->with([true, 'true', '1', 'on']);

    it('refuses a token without jti when the check is on', function (): void {
        config(['jwt.service.check_denylist' => true]);

        $this->withToken(serviceTokenWithout('jti'))->getJson('/internal')->assertUnauthorized();
    });

    it('lets a guard override the global switch', function (): void {
        config([
            'jwt.service.check_denylist' => false,
            'auth.guards.strict' => ['driver' => 'service-jwt', 'check_denylist' => true],
            'auth.guards.lenient' => ['driver' => 'service-jwt', 'check_denylist' => 'off'],
        ]);

        $token = revokedServiceToken()->token;
        $request = Request::create('/internal', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        expect(Auth::guard('strict')->setRequest($request)->user())->toBeNull()
            ->and(Auth::guard('lenient')->setRequest($request)->user()?->getAuthIdentifier())->toBe('opernity');

        config(['jwt.service.check_denylist' => true, 'auth.guards.blank' => ['driver' => 'service-jwt', 'check_denylist' => '']]);

        expect(Auth::guard('blank')->setRequest($request)->user())->toBeNull();
    });

    it('refuses a mistyped switch instead of reading it as off', function (string $key, string $config): void {
        config([$key => 'maybe']);

        Auth::guard($config)->user();
    })->with([
        'global' => ['jwt.service.check_denylist', 'service'],
        'per guard' => ['auth.guards.service.check_denylist', 'service'],
    ])->throws(JwtMisconfigured::class, 'check_denylist');
});
