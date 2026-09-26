<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Tests\Fixtures\Client;
use RoundlyConsulting\Jwt\Tests\Fixtures\User;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

/*
 * Two fully separated account types, each on its own `jwt` guard and its own
 * Eloquent provider — with colliding primary keys. Each guard resolves `sub`
 * through its OWN provider, so the audience is the only thing that stops a
 * users token (sub = 1) from authenticating as client #1.
 */

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
        'auth.providers.clients' => ['driver' => 'eloquent', 'model' => Client::class],
    ]);

    foreach (['users', 'clients'] as $table) {
        Schema::create($table, function ($table): void {
            $table->increments('id');
            $table->unsignedInteger('token_version')->default(1);
        });
    }

    User::query()->create();
    Client::query()->create();

    Route::middleware('auth:users')->get('/users/me', fn () => response()->json([
        'type' => auth()->user()::class,
        'id' => auth()->id(),
    ]));
    Route::middleware('auth:clients')->get('/clients/me', fn () => response()->json([
        'type' => auth()->user()::class,
        'id' => auth()->id(),
        'sub' => Jwt::claims('clients')?->string('sub'),
    ]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function guards(string $usersAudience, string $clientsAudience): void
{
    config([
        'auth.guards.users' => ['driver' => 'jwt', 'provider' => 'users', 'audience' => $usersAudience],
        'auth.guards.clients' => ['driver' => 'jwt', 'provider' => 'clients', 'audience' => $clientsAudience],
    ]);
}

function accessTokenFor(string $guard): string
{
    return Jwt::mintAccessToken(AccessTokenRequest::for(1)->audience(Jwt::audienceFor($guard)))->token;
}

it('shares a primary key between the two account tables', function (): void {
    expect(User::query()->sole()->id)->toBe(1)
        ->and(Client::query()->sole()->id)->toBe(1);
});

it('authenticates each token only on its own guard when the audiences differ', function (): void {
    guards('vetapp-users', 'vetapp-clients');

    $this->withToken(accessTokenFor('users'))->getJson('/users/me')
        ->assertOk()->assertJson(['type' => User::class, 'id' => 1]);
    $this->withToken(accessTokenFor('clients'))->getJson('/clients/me')
        ->assertOk()->assertJson(['type' => Client::class, 'id' => 1, 'sub' => '1']);
});

it('rejects a users token on the clients guard, and vice versa', function (): void {
    guards('vetapp-users', 'vetapp-clients');

    $this->withToken(accessTokenFor('users'))->getJson('/clients/me')->assertUnauthorized();
    $this->withToken(accessTokenFor('clients'))->getJson('/users/me')->assertUnauthorized();

    expect(Auth::guard('clients')->validate(['token' => accessTokenFor('users')]))->toBeFalse()
        ->and(Auth::guard('users')->validate(['token' => accessTokenFor('clients')]))->toBeFalse();
});

it('rejects a token minted for the global audience on either per-guard audience', function (): void {
    guards('vetapp-users', 'vetapp-clients');

    $global = Jwt::mintAccessToken(AccessTokenRequest::for(1))->token;

    $this->withToken($global)->getJson('/users/me')->assertUnauthorized();
    $this->withToken($global)->getJson('/clients/me')->assertUnauthorized();
});

/*
 * The hazard, documented: with one shared audience the guards cannot tell the
 * account types apart, and a users token authenticates as client #1. This is
 * why every guard of a multi-guard host needs its own audience.
 */
it('confuses the account types when both guards share an audience', function (): void {
    guards('shared', 'shared');

    $this->withToken(accessTokenFor('users'))->getJson('/clients/me')
        ->assertOk()->assertJson(['type' => Client::class, 'id' => 1]);
});
