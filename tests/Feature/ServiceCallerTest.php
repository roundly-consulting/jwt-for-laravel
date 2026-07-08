<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceCaller;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

function fakeIssuer(): ServiceTokenIssuer
{
    return new class implements ServiceTokenIssuer
    {
        public ?string $lastAudience = 'unset';

        public function issue(?string $audience = null): IssuedToken
        {
            $this->lastAudience = $audience;

            return new IssuedToken('service.token.value', CarbonImmutable::now()->addMinute(), 'jti');
        }
    };
}

it('attaches a fresh service token to a new request', function (): void {
    Http::fake();
    $caller = new ServiceCaller(fakeIssuer());

    $caller->request('cosmos-billing')->get('https://internal.test/ping');

    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer service.token.value'));
});

it('authenticates an existing pending request', function (): void {
    Http::fake();
    $caller = new ServiceCaller(fakeIssuer());

    $request = $caller->authenticate(Http::baseUrl('https://internal.test'));

    expect($request)->toBeInstanceOf(PendingRequest::class);

    $request->get('/ping');

    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer service.token.value'));
});
