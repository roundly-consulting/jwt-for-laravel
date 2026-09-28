<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Tests\Fixtures\User;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

/*
 * Provider mode: the guard resolves an Eloquent user, which carries no permissions
 * of its own. The hook used to consult only `ChecksPermissions` identities, so the
 * same token that granted `posts.edit` in claims mode granted nothing here.
 */
beforeEach(function (): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.denylist.store' => 'array',
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'users'],
        'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
    ]);

    Schema::create('users', function ($table): void {
        $table->increments('id');
    });

    $this->user = User::query()->create();

    Route::middleware('auth:api')->get('/abilities', fn () => response()->json([
        'edit' => request()->user()?->can('posts.edit'),
        'delete' => request()->user()?->can('posts.delete'),
        'gate' => Gate::allows('posts.edit'),
        'reloaded' => Gate::forUser(User::query()->findOrFail(request()->user()?->getAuthIdentifier()))->allows('posts.edit'),
    ]));
});

it('grants from the permissions claim of the token that authenticated an Eloquent user', function (): void {
    $token = Jwt::mintAccessToken(AccessTokenRequest::for((string) $this->user->id)->permissions('posts.edit'))->token;

    $this->withToken($token)->getJson('/abilities')
        ->assertOk()
        ->assertJson(['edit' => true, 'delete' => false, 'gate' => true]);
});

it('never grants a token\'s permissions to another instance of the same user', function (): void {
    $token = Jwt::mintAccessToken(AccessTokenRequest::for((string) $this->user->id)->permissions('posts.edit'))->token;

    $this->withToken($token)->getJson('/abilities')->assertOk()->assertJson(['reloaded' => false]);
});

it('grants nothing to an Eloquent user set without a token', function (): void {
    $this->actingAs($this->user, 'api')->getJson('/abilities')
        ->assertOk()
        ->assertJson(['edit' => false, 'gate' => false]);
});

it('grants nothing from a mistyped permissions claim', function (): void {
    $token = Jwt::mint((string) $this->user->id, 'access', 900, ['permissions' => 'posts.edit'])->token;

    $this->withToken($token)->getJson('/abilities')->assertOk()->assertJson(['edit' => false]);
});

it('grants nothing when the active guard is not a jwt guard', function (): void {
    expect(Gate::forUser($this->user)->allows('posts.edit'))->toBeFalse();
});
