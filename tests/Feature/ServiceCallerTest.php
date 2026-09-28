<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

function fakeIssuer(): ServiceTokenIssuer
{
    return new class implements ServiceTokenIssuer
    {
        public ?string $lastAudience = 'unset';

        /**
         * @param  array<string, mixed>  $claims
         */
        public function issue(?string $audience = null, array $claims = []): IssuedToken
        {
            $this->lastAudience = $audience;

            return new IssuedToken('service.token.value', CarbonImmutable::now()->addMinute(), 'jti');
        }
    };
}

it('attaches a fresh service token to a new request', function (): void {
    Http::fake();
    $issuer = fakeIssuer();
    app()->instance(ServiceTokenIssuer::class, $issuer);

    Jwt::services()->request('billing')->get('https://internal.test/ping');

    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer service.token.value'));
    expect($issuer->lastAudience)->toBe('billing');
});

it('authenticates an existing pending request', function (): void {
    Http::fake();
    app()->instance(ServiceTokenIssuer::class, fakeIssuer());

    $request = Jwt::services()->authenticate(Http::baseUrl('https://internal.test'));

    expect($request)->toBeInstanceOf(PendingRequest::class);

    $request->get('/ping');

    Http::assertSent(fn ($request) => $request->hasHeader('Authorization', 'Bearer service.token.value'));
});
