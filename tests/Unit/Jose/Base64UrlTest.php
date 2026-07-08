<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Base64Url;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;

it('round-trips arbitrary binary data', function (): void {
    $data = random_bytes(64);

    expect(Base64Url::decode(Base64Url::encode($data)))->toBe($data);
});

it('produces the url-safe alphabet without padding', function (): void {
    // 0xFF bytes force the `+`/`/` characters in standard base64.
    $encoded = Base64Url::encode("\xff\xff\xff");

    expect($encoded)
        ->not->toContain('+')
        ->not->toContain('/')
        ->not->toContain('=');
});

it('restores padding when decoding', function (): void {
    expect(Base64Url::decode(Base64Url::encode('a')))->toBe('a')
        ->and(Base64Url::decode(Base64Url::encode('ab')))->toBe('ab')
        ->and(Base64Url::decode(Base64Url::encode('abc')))->toBe('abc');
});

it('rejects standard-base64 characters', function (string $value): void {
    Base64Url::decode($value);
})->with([
    'plus' => 'ab+c',
    'slash' => 'ab/c',
    'padding' => 'YWI=',
])->throws(MalformedToken::class);

it('rejects an empty segment', function (): void {
    Base64Url::decode('');
})->throws(MalformedToken::class);

it('rejects an invalid base64url length', function (): void {
    // A single trailing character can never form a base64 group.
    Base64Url::decode('YWJjZ');
})->throws(MalformedToken::class);
