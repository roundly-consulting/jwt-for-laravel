<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceGuard;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceIdentity;

function fakeServiceVerifier(): ServiceTokenVerifier
{
    return new class implements ServiceTokenVerifier
    {
        public function verify(string $jwt): Claims
        {
            return match ($jwt) {
                'good' => new Claims(['iss' => 'logger', 'scope' => 'service']),
                'misconfigured' => throw ServiceAuthMisconfigured::missingSecret(),
                default => throw new InvalidSignature('bad token'),
            };
        }
    };
}

function serviceRequest(?string $token): Request
{
    $request = Request::create('/', 'GET');

    if ($token !== null) {
        $request->headers->set('Authorization', 'Bearer '.$token);
    }

    return $request;
}

it('authenticates a valid service token and exposes the payload', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest('good'));

    $user = $guard->user();

    expect($user)->toBeInstanceOf(ServiceIdentity::class)
        ->and($guard->user())->toBe($user)
        ->and($guard->payload())->not->toBeNull()
        ->and($user->getAuthIdentifier())->toBe('logger');
});

it('returns no user without a token', function (): void {
    expect((new ServiceGuard(fakeServiceVerifier(), serviceRequest(null)))->user())->toBeNull();
});

it('returns no user for a rejected token', function (): void {
    expect((new ServiceGuard(fakeServiceVerifier(), serviceRequest('bad')))->user())->toBeNull();
});

it('rethrows a misconfiguration rather than returning null', function (): void {
    (new ServiceGuard(fakeServiceVerifier(), serviceRequest('misconfigured')))->user();
})->throws(ServiceAuthMisconfigured::class);

it('validates credentials by token', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest(null));

    expect($guard->validate(['token' => 'good']))->toBeTrue()
        ->and($guard->validate(['token' => 'bad']))->toBeFalse()
        ->and($guard->validate([]))->toBeFalse();
});

it('re-resolves when the request changes', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest('good'));
    expect($guard->user())->toBeInstanceOf(ServiceIdentity::class);

    $guard->setRequest(serviceRequest(null));
    expect($guard->user())->toBeNull();
});

it('keeps an identity set with setUser, with its claims, even after the request changes', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest(null));
    $identity = ServiceIdentity::fromClaims(new Claims(['iss' => 'billing']));

    $guard->setUser($identity);

    expect($guard->user())->toBe($identity)
        ->and($guard->hasUser())->toBeTrue()
        ->and($guard->payload()?->string('iss'))->toBe('billing');

    $guard->setRequest(serviceRequest('good'));

    expect($guard->user())->toBe($identity);
});

it('has no payload for a set user that carries no claims', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest('good'));
    $guard->user();

    $guard->setUser(new GenericUser(['id' => 'billing']));

    expect($guard->payload())->toBeNull();
});

it('forgets a set identity and falls back to the bearer token', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest('good'));
    $guard->setUser(new GenericUser(['id' => 'billing']));

    $guard->forgetUser();

    expect($guard->hasUser())->toBeFalse()
        ->and($guard->payload())->toBeNull()
        ->and($guard->user()?->getAuthIdentifier())->toBe('logger');
});

it('does not report an earlier request\'s caller as present', function (): void {
    $guard = new ServiceGuard(fakeServiceVerifier(), serviceRequest('good'));
    $guard->user();

    $guard->setRequest(serviceRequest(null));

    expect($guard->hasUser())->toBeFalse();
});
