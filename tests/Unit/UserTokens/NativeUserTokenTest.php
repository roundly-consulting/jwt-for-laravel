<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
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
