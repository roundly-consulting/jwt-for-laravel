<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Carbon\CarbonInterval;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Jwt\Events\ServiceTokenIssued;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceIdentity;
use RoundlyConsulting\Jwt\Tests\Fixtures\User;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/*
 * Per-call `ttl` and `subject` for service tokens (2.1.0): one short-lived token per
 * agent run, bound to the run, revoked when it ends.
 */
beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'app.service' => 'opernity',
        'jwt.service.secret' => 'a-very-secret-service-key-0123456789',
        'jwt.service.audience' => 'opernity',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'auth.guards.service' => ['driver' => 'service-jwt'],
    ]);
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

const RUN_SUBJECT = 'agent-run:01JCQ6Z4W8G8V1Y0R5K3M2N7PA';

it('issues a token that expires after its per-call ttl of 60 seconds', function (): void {
    config(['jwt.service.ttl' => 600]);

    $issued = Jwt::services()->issue(ttl: 60, subject: RUN_SUBJECT);

    expect($issued->expiresAt->getTimestamp())->toBe(1_700_000_060)
        ->and(Jwt::services()->verify($issued->token)->int('exp'))->toBe(1_700_000_060);

    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_059));
    expect(Jwt::services()->verify($issued->token)->string('sub'))->toBe(RUN_SUBJECT);

    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_060));
    expect(fn () => Jwt::services()->verify($issued->token))->toThrow(TokenExpired::class);
});

it('keeps the configured ttl when no per-call ttl is given', function (): void {
    expect(Jwt::services()->issue(subject: RUN_SUBJECT)->expiresAt->getTimestamp())->toBe(1_700_000_060);
});

it('takes the ttl as an interval', function (DateInterval $ttl, int $seconds): void {
    expect(Jwt::services()->issue(ttl: $ttl)->expiresAt->getTimestamp())->toBe(1_700_000_000 + $seconds);
})->with([
    'CarbonInterval minutes' => [CarbonInterval::minutes(15), 900],
    'CarbonInterval seconds' => [CarbonInterval::seconds(60), 60],
    'DateInterval' => [new DateInterval('PT1H'), 3600],
]);

it('sets sub only through the subject option and reads it back', function (): void {
    $issued = Jwt::services()->issue(claims: ['person' => 'p-7', 'company' => 'c-3'], ttl: 300, subject: RUN_SUBJECT);
    $claims = Jwt::services()->verify($issued->token);

    expect($claims->string('sub'))->toBe(RUN_SUBJECT)
        ->and($claims->string('person'))->toBe('p-7')
        ->and($claims->string('company'))->toBe('c-3')
        ->and($claims->string('scope'))->toBe('service')
        ->and($claims->string('jti'))->toBe($issued->jti)
        ->and(Jwt::services()->verify(Jwt::services()->issue()->token)->has('sub'))->toBeFalse();
});

it('reads the subject through the service guard while the identity stays the calling service', function (): void {
    Route::middleware('auth:service')->get('/agent', fn () => response()->json([
        'id' => auth('service')->id(),
        'subject' => auth('service')->user() instanceof ServiceIdentity ? auth('service')->user()->subject() : 'not-a-service',
        'sub' => Jwt::services()->claims()?->string('sub'),
    ]));

    $token = Jwt::services()->issue(ttl: 120, subject: RUN_SUBJECT)->token;

    $this->withToken($token)->getJson('/agent')->assertOk()->assertExactJson([
        'id' => 'opernity',
        'subject' => RUN_SUBJECT,
        'sub' => RUN_SUBJECT,
    ]);
});

it('answers a null subject for a token without one', function (): void {
    $identity = ServiceIdentity::fromClaims(new Claims(['iss' => 'billing', 'sub' => 42]));

    expect($identity->subject())->toBeNull()
        ->and(ServiceIdentity::fromClaims(new Claims(['iss' => 'billing']))->subject())->toBeNull();
});

it('refuses a ttl outside 1..max_ttl', function (int|DateInterval $ttl): void {
    Jwt::services()->issue(ttl: $ttl, subject: RUN_SUBJECT);
})->with([
    'zero' => [0],
    'negative' => [-60],
    'one over the default max' => [3601],
    'PHP_INT_MAX' => [PHP_INT_MAX],
    'negative interval' => [CarbonInterval::seconds(60)->invert()],
    'fractional interval' => [CarbonInterval::milliseconds(1500)],
    'zero interval' => [CarbonInterval::seconds(0)],
    'interval over the max' => [CarbonInterval::hours(2)],
])->throws(ServiceAuthMisconfigured::class, 'whole number of seconds from 1 to 3600');

it('bounds the per-call ttl by jwt.service.max_ttl', function (): void {
    config(['jwt.service.max_ttl' => '120']);
    app()->forgetInstance(NativeServiceTokenService::class);

    expect(Jwt::services()->issue(ttl: 120)->expiresAt->getTimestamp())->toBe(1_700_000_120)
        ->and(fn () => Jwt::services()->issue(ttl: 121))->toThrow(ServiceAuthMisconfigured::class, 'from 1 to 120');
});

it('does not bound the configured default ttl by max_ttl', function (): void {
    config(['jwt.service.ttl' => 7200, 'jwt.service.max_ttl' => 60]);
    app()->forgetInstance(NativeServiceTokenService::class);

    expect(Jwt::services()->issue()->expiresAt->getTimestamp())->toBe(1_700_007_200);
});

it('refuses a malformed max_ttl', function (mixed $value): void {
    config(['jwt.service.max_ttl' => $value]);
    app()->forgetInstance(NativeServiceTokenService::class);

    Jwt::services()->issue();
})->with(['soon', 0, -1])->throws(JwtMisconfigured::class, 'jwt.service.max_ttl');

it('refuses an invalid subject without echoing it', function (string $subject, string $reason): void {
    expect(fn () => Jwt::services()->issue(ttl: 60, subject: $subject))
        ->toThrow(function (ServiceAuthMisconfigured $e) use ($subject, $reason): void {
            expect($e->getMessage())->toContain($reason);

            if (trim($subject) !== '') {
                expect($e->getMessage())->not->toContain($subject);
            }
        });
})->with([
    'empty' => ['', 'it is empty'],
    'whitespace' => ['   ', 'it is empty'],
    'oversized' => [str_repeat('r', 256), 'longer than 255 bytes'],
    'oversized multibyte' => [str_repeat('č', 128), 'longer than 255 bytes'],
    'invalid UTF-8' => ["run-\xff\xfe", 'not valid UTF-8'],
    'newline' => ["run\n1", 'control character'],
    'NUL' => ["run\0x", 'control character'],
    'leading space' => [' run-1', 'leading or trailing whitespace'],
    'trailing space' => ['run-1 ', 'leading or trailing whitespace'],
]);

it('accepts a subject of exactly 255 bytes', function (): void {
    $subject = str_repeat('r', 255);

    expect(Jwt::services()->verify(Jwt::services()->issue(subject: $subject)->token)->string('sub'))->toBe($subject);
});

it('still refuses sub as a raw claim, with or without the subject option', function (?string $subject): void {
    Jwt::services()->issue(claims: ['sub' => 'user-1'], ttl: 60, subject: $subject);
})->with(['without the option' => [null], 'with the option' => [RUN_SUBJECT]])
    ->throws(ServiceAuthMisconfigured::class, '[sub] are registered claims');

it('still refuses every other registered claim alongside the options', function (string $claim): void {
    Jwt::services()->issue(claims: [$claim => 'x'], ttl: 60, subject: RUN_SUBJECT);
})->with(['iss', 'aud', 'exp', 'jti', 'scope', 'permissions'])->throws(ServiceAuthMisconfigured::class, 'registered claims');

it('gives every service token its own jti', function (): void {
    $first = Jwt::services()->issue(ttl: 60, subject: RUN_SUBJECT);
    $second = Jwt::services()->issue(ttl: 60, subject: RUN_SUBJECT);
    $plain = Jwt::services()->issue();

    expect($first->jti)->toBeString()->not->toBe('')
        ->and($first->jti)->not->toBe($second->jti)
        ->and(Jwt::services()->verify($first->token)->string('jti'))->toBe($first->jti)
        ->and(Jwt::services()->verify($plain->token)->string('jti'))->toBe($plain->jti);
});

it('announces the subject with ServiceTokenIssued', function (): void {
    Event::fake();

    $issued = Jwt::services()->issue(ttl: 60, subject: RUN_SUBJECT);
    Jwt::services()->issue();

    Event::assertDispatched(ServiceTokenIssued::class, fn (ServiceTokenIssued $e): bool => $e->subject === RUN_SUBJECT
        && $e->jti === $issued->jti
        && $e->expiresAt->getTimestamp() === 1_700_000_060);
    Event::assertDispatched(ServiceTokenIssued::class, fn (ServiceTokenIssued $e): bool => $e->subject === null);
});

it('refuses the options when the bound issuer cannot honour them', function (): void {
    app()->bind(ServiceTokenIssuer::class, fn () => new class implements ServiceTokenIssuer
    {
        public function issue(?string $audience = null, array $claims = []): IssuedToken
        {
            return new IssuedToken('host.issued.token', CarbonImmutable::now()->addMinute(), 'host-jti');
        }
    });

    expect(Jwt::services()->issue()->jti)->toBe('host-jti')
        ->and(fn () => Jwt::services()->issue(ttl: 60))->toThrow(ServiceAuthMisconfigured::class, 'does not accept a ttl or subject')
        ->and(fn () => Jwt::services()->issue(subject: RUN_SUBJECT))->toThrow(ServiceAuthMisconfigured::class, 'ServiceTokenIssuerWithOptions');
});

it('records the options under Jwt::fake()', function (): void {
    $fake = Jwt::fake();

    $issued = Jwt::services()->issue(ttl: 90, subject: RUN_SUBJECT);

    $fake->assertServiceTokenIssued('opernity', fn (Claims $claims): bool => $claims->get('sub') === RUN_SUBJECT
        && $claims->get('exp') === 1_700_000_090);

    expect($fake->serviceTokens()[0]->token->jti)->toBe($issued->jti);
});

/*
 * A service token's `sub` never authenticates as a user. The `jwt` guard pins RS256 and
 * `scope=access`, so an HS256 `scope=service` token is refused before `sub` is read, in
 * provider mode and in claims mode alike, even when `sub` IS a real user's key.
 */
describe('subject namespace', function (): void {
    beforeEach(function (): void {
        config([
            'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'users', 'audience' => 'opernity'],
            'auth.guards.claims' => ['driver' => 'jwt', 'audience' => 'opernity'],
            'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
        ]);

        Schema::create('users', function ($table): void {
            $table->increments('id');
        });

        User::query()->create();

        Route::middleware('auth:api')->get('/me', fn () => response()->json(['id' => auth('api')->id()]));
        Route::middleware('auth:claims')->get('/claims', fn () => response()->json(['id' => auth('claims')->id()]));
    });

    it('lets a real user token in, as the control', function (): void {
        $token = Jwt::mint('1', 'access', 900, audience: 'opernity')->token;

        $this->withToken($token)->getJson('/me')->assertOk()->assertExactJson(['id' => 1]);
    });

    it('never authenticates a service token as the user its sub names', function (string $route): void {
        $token = Jwt::services()->issue(ttl: 60, subject: '1')->token;

        $this->withToken($token)->getJson($route)->assertUnauthorized();
    })->with(['provider mode' => ['/me'], 'claims mode' => ['/claims']]);

    it('refuses a service token at the user verifier before reading sub', function (): void {
        $token = Jwt::services()->issue(ttl: 60, subject: '1')->token;

        expect(fn () => Jwt::verify($token, 'opernity'))->toThrow(AlgorithmMismatch::class)
            ->and(fn () => Jwt::guard('api')->verify($token, checkDenylist: true))->toThrow(AlgorithmMismatch::class)
            ->and(auth('api')->validate(['token' => $token]))->toBeFalse();
    });
});
