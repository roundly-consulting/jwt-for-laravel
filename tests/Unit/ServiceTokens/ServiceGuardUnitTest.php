<?php

declare(strict_types=1);

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
