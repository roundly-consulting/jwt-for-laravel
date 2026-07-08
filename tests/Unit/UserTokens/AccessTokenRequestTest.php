<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

it('builds from a subject with sensible defaults', function (): void {
    $request = AccessTokenRequest::for('user-1');

    expect($request->subject)->toBe('user-1')
        ->and($request->email)->toBeNull()
        ->and($request->emailVerified)->toBeFalse()
        ->and($request->tokenVersion)->toBe(0)
        ->and($request->permissions)->toBe([])
        ->and($request->extraClaims)->toBe([]);
});

it('casts an integer subject to a string', function (): void {
    expect(AccessTokenRequest::for(42)->subject)->toBe('42');
});

it('is immutable — each wither returns a new instance', function (): void {
    $base = AccessTokenRequest::for('user-1');
    $withEmail = $base->email('a@b.test', verified: true);

    expect($withEmail)->not->toBe($base)
        ->and($base->email)->toBeNull()
        ->and($withEmail->email)->toBe('a@b.test')
        ->and($withEmail->emailVerified)->toBeTrue();
});

it('fluently assembles the full claim map', function (): void {
    $claims = AccessTokenRequest::for('user-1')
        ->email('a@b.test', verified: true)
        ->tokenVersion(3)
        ->permissions('posts.view', 'posts.edit')
        ->withClaims(['org' => 42])
        ->toClaims();

    expect($claims)->toBe([
        'org' => 42,
        'email' => 'a@b.test',
        'email_verified' => true,
        'tv' => 3,
        'permissions' => ['posts.view', 'posts.edit'],
    ]);
});

it('merges successive withClaims calls', function (): void {
    $request = AccessTokenRequest::for('user-1')
        ->withClaims(['org' => 1])
        ->withClaims(['team' => 2]);

    expect($request->extraClaims)->toBe(['org' => 1, 'team' => 2]);
});
