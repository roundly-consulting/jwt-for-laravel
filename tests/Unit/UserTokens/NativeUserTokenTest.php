<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use Ramsey\Uuid\Uuid;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\NativeUserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\Scope;

function keys(): KeyRepository
{
    return new KeyRepository(
        fixturesDir().'/keys/jwt-private.pem',
        fixturesDir().'/keys/jwt-public.pem',
    );
}

function issuer(): NativeUserTokenIssuer
{
    return new NativeUserTokenIssuer(new Encoder, keys(), 'jwt-issuer', 'web', 900, 300, 3600);
}

function verifier(string $issuerName = 'jwt-issuer', string $audience = 'web'): NativeUserTokenVerifier
{
    return new NativeUserTokenVerifier(new Decoder, keys(), $issuerName, $audience, 0);
}

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('mints a token with the full registered claim set', function (): void {
    $issued = issuer()->mint('user-1', 'access', 900);

    $claims = verifier()->verify($issued->token);

    expect($claims->string('iss'))->toBe('jwt-issuer')
        ->and($claims->string('aud'))->toBe('web')
        ->and($claims->string('sub'))->toBe('user-1')
        ->and($claims->string('scope'))->toBe('access')
        ->and($claims->int('iat'))->toBe(1_700_000_000)
        ->and($claims->int('nbf'))->toBe(1_700_000_000)
        ->and($claims->int('exp'))->toBe(1_700_000_900)
        ->and($claims->string('jti'))->toBe($issued->jti)
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_900);
});

it('produces a uuid jti', function (): void {
    expect(issuer()->mint('user-1', 'access', 900)->jti)
        ->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/');
});

it('mints an access token with the platform claim shape', function (): void {
    $issued = issuer()->mintAccessToken(
        AccessTokenRequest::for('user-1')
            ->email('a@b.test', verified: true)
            ->tokenVersion(7)
            ->permissions('posts.view', 'posts.edit')
            ->withClaims(['org' => 42]),
    );

    $claims = verifier()->verify($issued->token);

    expect($claims->string('email'))->toBe('a@b.test')
        ->and($claims->get('email_verified'))->toBeTrue()
        ->and($claims->int('tv'))->toBe(7)
        ->and($claims->list('permissions'))->toBe(['posts.view', 'posts.edit'])
        ->and($claims->int('org'))->toBe(42)
        ->and($claims->string('scope'))->toBe(Scope::Access->value);
});

it('mints a challenge token that consumes the configured challenge ttl', function (): void {
    $issued = issuer()->mintChallengeToken('user-1', ['method' => 'totp']);

    $claims = verifier()->verify($issued->token);

    expect($claims->string('scope'))->toBe(Scope::TwoFaPending->value)
        ->and($claims->string('sub'))->toBe('user-1')
        ->and($claims->string('method'))->toBe('totp')
        ->and($claims->int('exp'))->toBe(1_700_000_000 + 300)
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_000 + 300);
});

it('mints an email-verify token that consumes the configured verify ttl', function (): void {
    $issued = issuer()->mintEmailVerifyToken('user-1', 'a@b.test');

    $claims = verifier()->verify($issued->token);

    expect($claims->string('scope'))->toBe(Scope::EmailVerify->value)
        ->and($claims->string('email'))->toBe('a@b.test')
        ->and($claims->int('exp'))->toBe(1_700_000_000 + 3600);
});

it('never lets extra claims override registered claims', function (): void {
    $issued = issuer()->mint('user-1', 'access', 900, ['iss' => 'evil', 'sub' => 'admin']);

    $claims = verifier()->verify($issued->token);

    expect($claims->string('iss'))->toBe('jwt-issuer')
        ->and($claims->string('sub'))->toBe('user-1');
});

it('rejects a token with the wrong issuer', function (): void {
    $issued = issuer()->mint('user-1', 'access', 900);

    verifier('other-issuer')->verify($issued->token);
})->throws(ClaimMismatch::class);

it('rejects a token with the wrong audience', function (): void {
    $issued = issuer()->mint('user-1', 'access', 900);

    verifier('jwt-issuer', 'other-audience')->verify($issued->token);
})->throws(ClaimMismatch::class);

it('stamps an explicit audience instead of the configured one', function (): void {
    $issued = issuer()->mint('user-1', 'access', 900, [], 'clients');

    expect(verifier(audience: 'clients')->verify($issued->token)->string('aud'))->toBe('clients');
});

it('refuses to mint for an explicitly empty audience', function (): void {
    issuer()->mint('user-1', 'access', 900, [], '');
})->throws(JwtMisconfigured::class, 'JWT_AUDIENCE');

it('mints an access token for the request audience and ttl', function (): void {
    $issued = issuer()->mintAccessToken(AccessTokenRequest::for('user-1')->audience('clients')->ttl(60));

    $claims = verifier()->verify($issued->token, 'clients');

    expect($claims->string('aud'))->toBe('clients')
        ->and($claims->int('exp'))->toBe(1_700_000_060)
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_060)
        ->and($claims->has('ttl'))->toBeFalse();
});

it('falls back to the configured audience and ttl for an access token', function (): void {
    $claims = verifier()->verify(issuer()->mintAccessToken(AccessTokenRequest::for('user-1'))->token);

    expect($claims->string('aud'))->toBe('web')
        ->and($claims->int('exp'))->toBe(1_700_000_900);
});

it('round-trips the OIDC session claims', function (): void {
    $issued = issuer()->mintAccessToken(
        AccessTokenRequest::for('user-1')->sessionId('family-1')->authMethods('pwd', 'otp', 'mfa')->authTime(1_699_999_000),
    );

    $claims = verifier()->verify($issued->token);

    expect($claims->sessionId())->toBe('family-1')
        ->and($claims->authMethods())->toBe(['pwd', 'otp', 'mfa'])
        ->and($claims->authTime())->toBe(1_699_999_000);
});

it('verifies against an explicit audience, rejecting the configured one', function (): void {
    $forClients = issuer()->mint('user-1', 'access', 900, [], 'clients');
    $forWeb = issuer()->mint('user-1', 'access', 900);

    expect(verifier()->verify($forClients->token, 'clients')->string('aud'))->toBe('clients')
        ->and(fn () => verifier()->verify($forClients->token))->toThrow(ClaimMismatch::class)
        ->and(fn () => verifier()->verify($forWeb->token, 'clients'))->toThrow(ClaimMismatch::class);
});

it('refuses to verify against an explicitly empty audience', function (): void {
    verifier()->verify(issuer()->mint('user-1', 'access', 900)->token, '');
})->throws(JwtMisconfigured::class, 'JWT_AUDIENCE');

/**
 * The token below was minted by the issuer as it stood BEFORE audience, ttl and
 * the OIDC session claims existed. A request that uses none of them must still
 * produce it byte-for-byte: same claims, same key order, same signature.
 */
it('mints a request without the new setters byte-identically to the frozen token', function (): void {
    Str::createUuidsUsing(fn () => Uuid::fromString('33333333-3333-4333-8333-333333333333'));

    try {
        $issued = issuer()->mintAccessToken(
            AccessTokenRequest::for('user-1')
                ->email('a@b.test', verified: true)
                ->tokenVersion(1)
                ->permissions('posts.view')
                ->withClaims(['org' => 42]),
        );
    } finally {
        Str::createUuidsNormally();
    }

    expect($issued->token)->toBe(trim(readFixture('tokens/frozen_access_request.jwt')))
        ->and(array_keys(verifier()->verify($issued->token)->all()))->toBe([
            'org', 'email', 'email_verified', 'tv', 'permissions',
            'iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti', 'scope',
        ]);
});

it('refuses to build an issuer or verifier with an empty configured pin', function (Closure $build, string $message): void {
    expect($build)->toThrow(JwtMisconfigured::class, $message);
})->with([
    'issuer, no iss' => [fn () => new NativeUserTokenIssuer(new Encoder, keys(), '', 'web', 900, 300, 3600), 'JWT_ISSUER'],
    'issuer, no aud' => [fn () => new NativeUserTokenIssuer(new Encoder, keys(), 'jwt-issuer', '', 900, 300, 3600), 'JWT_AUDIENCE'],
    'verifier, no iss' => [fn () => verifier(''), 'JWT_ISSUER'],
    'verifier, no aud' => [fn () => verifier('jwt-issuer', ''), 'JWT_AUDIENCE'],
]);
