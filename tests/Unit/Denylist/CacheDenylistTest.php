<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use RoundlyConsulting\Jwt\Denylist\CacheDenylist;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

function denylist(): CacheDenylist
{
    return new CacheDenylist(app(CacheFactory::class), 'array', 'jwt:denylist:');
}

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('reports an unknown jti as not denied', function (): void {
    expect(denylist()->has('jti-1'))->toBeFalse();
});

it('denies a jti until its expiry', function (): void {
    $denylist = denylist();
    $denylist->deny('jti-1', CarbonImmutable::now()->addSeconds(60));

    expect($denylist->has('jti-1'))->toBeTrue();
});

it('evicts the entry after the token would have expired', function (): void {
    $denylist = denylist();
    $denylist->deny('jti-1', CarbonImmutable::now()->addSeconds(60));

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(61));

    expect($denylist->has('jti-1'))->toBeFalse();
});

it('is a no-op for an already-expired token', function (): void {
    $denylist = denylist();
    $denylist->deny('jti-1', CarbonImmutable::now()->subSecond());

    expect($denylist->has('jti-1'))->toBeFalse();
});

it('prefixes stored keys', function (): void {
    $denylist = denylist();
    $denylist->deny('abc', CarbonImmutable::now()->addSeconds(60));

    expect(app(CacheFactory::class)->store('array')->has('jwt:denylist:abc'))->toBeTrue();
});

it('denies a freshly issued token until its own expiry', function (): void {
    $denylist = denylist();
    $token = new IssuedToken('the.jwt.value', CarbonImmutable::now()->addSeconds(60), 'jti-token');

    $denylist->denyToken($token);

    expect($denylist->has('jti-token'))->toBeTrue();
});

it('works without an event dispatcher bound', function (): void {
    // Null dispatcher (the constructor default) must never crash a deny.
    $denylist = new CacheDenylist(app(CacheFactory::class), 'array', 'jwt:denylist:', null);

    $denylist->deny('jti-nulld', CarbonImmutable::now()->addSeconds(60));

    expect($denylist->has('jti-nulld'))->toBeTrue();
});

it('holds a denial for the verification leeway past the token expiry', function (): void {
    $denylist = new CacheDenylist(app(CacheFactory::class), 'array', 'jwt:denylist:', null, leeway: 30);
    $denylist->deny('jti-1', CarbonImmutable::now()->addSeconds(60));

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(89));
    expect($denylist->has('jti-1'))->toBeTrue();

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(2));
    expect($denylist->has('jti-1'))->toBeFalse();
});

it('still denies a token past its expiry while the leeway keeps it verifiable', function (): void {
    $denylist = new CacheDenylist(app(CacheFactory::class), 'array', 'jwt:denylist:', null, leeway: 30);
    $denylist->deny('jti-1', CarbonImmutable::now()->subSeconds(10));

    expect($denylist->has('jti-1'))->toBeTrue();
});
