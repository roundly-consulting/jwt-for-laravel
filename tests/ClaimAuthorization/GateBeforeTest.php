<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

function tokenUserWith(array $permissions): TokenUser
{
    return TokenUser::fromClaims(new Claims(['sub' => 'user-1', 'permissions' => $permissions]));
}

it('grants an ability listed in the permissions claim', function (): void {
    expect(Gate::forUser(tokenUserWith(['posts.view']))->allows('posts.view'))->toBeTrue();
});

it('does not grant an ability that is not listed', function (): void {
    expect(Gate::forUser(tokenUserWith(['posts.view']))->allows('posts.delete'))->toBeFalse();
});

it('returns null on a miss so other gates still run', function (): void {
    Gate::define('posts.publish', fn () => true);

    // The claim does not include posts.publish, but the explicit gate still grants it.
    expect(Gate::forUser(tokenUserWith([]))->allows('posts.publish'))->toBeTrue();
});
