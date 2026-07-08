<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;

it('builds an identity from claims', function (): void {
    $user = TokenUser::fromClaims(new Claims(['sub' => 'user-1', 'permissions' => ['posts.view']]));

    expect($user->getAuthIdentifier())->toBe('user-1')
        ->and($user->getAuthIdentifierName())->toBe('sub')
        ->and($user->hasPermission('posts.view'))->toBeTrue()
        ->and($user->hasPermission('posts.delete'))->toBeFalse();
});

it('defaults to no permissions when the claim is absent', function (): void {
    $user = TokenUser::fromClaims(new Claims(['sub' => 'user-1']));

    expect($user->hasPermission('anything'))->toBeFalse();
});

it('exposes the backing claims', function (): void {
    $claims = new Claims(['sub' => 'user-1']);

    expect(TokenUser::fromClaims($claims)->claims())->toBe($claims);
});

it('is a stateless identity with no password or remember token', function (): void {
    $user = TokenUser::fromClaims(new Claims(['sub' => 'user-1']));
    $user->setRememberToken('ignored');

    expect($user->getAuthPassword())->toBe('')
        ->and($user->getAuthPasswordName())->toBe('password')
        ->and($user->getRememberToken())->toBe('')
        ->and($user->getRememberTokenName())->toBe('');
});
