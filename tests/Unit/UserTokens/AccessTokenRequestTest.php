<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
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

it('leaves every new field unset by default', function (): void {
    $request = AccessTokenRequest::for('user-1');

    expect($request->audience)->toBeNull()
        ->and($request->ttl)->toBeNull()
        ->and($request->sessionId)->toBeNull()
        ->and($request->authMethods)->toBeNull()
        ->and($request->authTime)->toBeNull();
});

it('carries an audience and ttl as minting parameters, never as payload', function (): void {
    $request = AccessTokenRequest::for('user-1')->audience('clients')->ttl(600);

    expect($request->audience)->toBe('clients')
        ->and($request->ttl)->toBe(600)
        ->and($request->toClaims())->not->toHaveKeys(['aud', 'audience', 'ttl', 'exp']);
});

it('rejects a ttl below one second', function (int $seconds): void {
    AccessTokenRequest::for('user-1')->ttl($seconds);
})->with([0, -1])->throws(InvalidArgumentException::class, 'at least one second');

it('accepts a one-second ttl', function (): void {
    expect(AccessTokenRequest::for('user-1')->ttl(1)->ttl)->toBe(1);
});

it('emits the OIDC session claims when set', function (): void {
    $claims = AccessTokenRequest::for('user-1')
        ->sessionId('family-1')
        ->authMethods('pwd', 'otp', 'mfa')
        ->authTime(1_700_000_000)
        ->toClaims();

    expect($claims['sid'])->toBe('family-1')
        ->and($claims['amr'])->toBe(['pwd', 'otp', 'mfa'])
        ->and($claims['auth_time'])->toBe(1_700_000_000);
});

it('omits the OIDC session claims when unset', function (): void {
    expect(AccessTokenRequest::for('user-1')->toClaims())->not->toHaveKeys(['sid', 'amr', 'auth_time']);
});

it('casts an integer session id to a string', function (): void {
    expect(AccessTokenRequest::for('user-1')->sessionId(42)->toClaims()['sid'])->toBe('42');
});

it('rejects an empty session id', function (): void {
    AccessTokenRequest::for('user-1')->sessionId('');
})->throws(InvalidArgumentException::class, 'session id');

it('reads auth_time from a date as unix seconds', function (): void {
    $at = CarbonImmutable::createFromTimestamp(1_699_999_000);

    expect(AccessTokenRequest::for('user-1')->authTime($at)->authTime)->toBe(1_699_999_000)
        ->and(AccessTokenRequest::for('user-1')->authTime(new DateTimeImmutable('@1699999000'))->authTime)->toBe(1_699_999_000);
});

it('de-duplicates auth methods, keeping first occurrence order', function (): void {
    expect(AccessTokenRequest::for('user-1')->authMethods('otp', 'pwd', 'otp')->authMethods)->toBe(['otp', 'pwd']);
});

it('rejects an empty auth method list or a blank method', function (array $methods): void {
    AccessTokenRequest::for('user-1')->authMethods(...$methods);
})->with([
    'none' => [[]],
    'blank' => [['pwd', '']],
])->throws(InvalidArgumentException::class, 'Authentication methods');

it('lets the known session claims win over withClaims extras', function (): void {
    $claims = AccessTokenRequest::for('user-1')
        ->withClaims(['sid' => 'spoofed', 'amr' => ['none'], 'auth_time' => 1, 'tv' => 99])
        ->sessionId('real')
        ->authMethods('pwd')
        ->authTime(2)
        ->toClaims();

    expect($claims['sid'])->toBe('real')
        ->and($claims['amr'])->toBe(['pwd'])
        ->and($claims['auth_time'])->toBe(2)
        ->and($claims['tv'])->toBe(0);
});

it('keeps every field across later withers', function (): void {
    $request = AccessTokenRequest::for('user-1')
        ->audience('clients')
        ->ttl(60)
        ->sessionId('s')
        ->authMethods('pwd')
        ->authTime(5)
        ->email('a@b.test', verified: true)
        ->tokenVersion(2)
        ->permissions('p')
        ->withClaims(['x' => 1]);

    expect($request->audience)->toBe('clients')
        ->and($request->ttl)->toBe(60)
        ->and($request->sessionId)->toBe('s')
        ->and($request->authMethods)->toBe(['pwd'])
        ->and($request->authTime)->toBe(5)
        ->and($request->email)->toBe('a@b.test')
        ->and($request->emailVerified)->toBeTrue()
        ->and($request->tokenVersion)->toBe(2)
        ->and($request->permissions)->toBe(['p'])
        ->and($request->extraClaims)->toBe(['x' => 1]);
});

it('can reset email verification to false through email()', function (): void {
    $request = AccessTokenRequest::for('user-1')->email('a@b.test', verified: true)->email('c@d.test');

    expect($request->email)->toBe('c@d.test')
        ->and($request->emailVerified)->toBeFalse();
});
