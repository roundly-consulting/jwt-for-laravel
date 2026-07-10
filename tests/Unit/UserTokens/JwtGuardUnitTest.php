<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\JwtGuard;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

function fakeVerifier(): UserTokenVerifier
{
    return new class implements UserTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            if ($jwt === 'good') {
                return new Claims(['sub' => 'user-1', 'scope' => 'access', 'jti' => 'j1']);
            }

            throw new InvalidSignature('bad token');
        }
    };
}

function noopDenylist(): Denylist
{
    return new class implements Denylist
    {
        public function has(string $jti): bool
        {
            return false;
        }

        public function deny(string $jti, CarbonImmutable $until): void {}

        public function denyToken(IssuedToken $token): void {}
    };
}

function requestWithToken(?string $token): Request
{
    $request = Request::create('/', 'GET');

    if ($token !== null) {
        $request->headers->set('Authorization', 'Bearer '.$token);
    }

    return $request;
}

function guardFor(Request $request): JwtGuard
{
    return new JwtGuard(fakeVerifier(), noopDenylist(), $request, 'access', TokenUser::class, true, null, null);
}

it('resolves, caches and exposes the payload for a valid token', function (): void {
    $guard = guardFor(requestWithToken('good'));

    $user = $guard->user();

    expect($user)->toBeInstanceOf(TokenUser::class)
        ->and($guard->user())->toBe($user)
        ->and($guard->check())->toBeTrue()
        ->and($guard->payload()?->string('sub'))->toBe('user-1');
});

it('returns no user for a bad token', function (): void {
    expect(guardFor(requestWithToken('bad'))->user())->toBeNull();
});

it('validates credentials by token', function (): void {
    $guard = guardFor(requestWithToken(null));

    expect($guard->validate(['token' => 'good']))->toBeTrue()
        ->and($guard->validate(['token' => 'bad']))->toBeFalse()
        ->and($guard->validate([]))->toBeFalse();
});

it('returns no user when the subject claim is not a string', function (): void {
    $verifier = new class implements UserTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            return new Claims(['sub' => 123, 'scope' => 'access', 'jti' => 'j1']);
        }
    };

    $guard = new JwtGuard($verifier, noopDenylist(), requestWithToken('good'), 'access', TokenUser::class, true, null, null);

    expect($guard->user())->toBeNull();
});

it('rejects a token without a string jti when the denylist is enabled', function (): void {
    // A validly signed token whose `jti` can't be denylisted must fail closed,
    // otherwise a co-issuer omitting `jti` could mint irrevocable tokens.
    $verifier = new class implements UserTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            return new Claims(['sub' => 'user-1', 'scope' => 'access']);
        }
    };

    $guard = new JwtGuard($verifier, noopDenylist(), requestWithToken('good'), 'access', TokenUser::class, true, null, null);

    expect($guard->user())->toBeNull();
});

it('still authenticates a jti-less token when denylisting is disabled', function (): void {
    $verifier = new class implements UserTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            return new Claims(['sub' => 'user-1', 'scope' => 'access']);
        }
    };

    $guard = new JwtGuard($verifier, noopDenylist(), requestWithToken('good'), 'access', TokenUser::class, false, null, null);

    expect($guard->user())->toBeInstanceOf(TokenUser::class);
});

it('re-resolves when the request instance changes', function (): void {
    $guard = guardFor(requestWithToken('good'));

    expect($guard->user())->toBeInstanceOf(TokenUser::class);

    $guard->setRequest(requestWithToken(null));

    expect($guard->user())->toBeNull();
});
