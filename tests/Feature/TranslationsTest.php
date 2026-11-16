<?php

declare(strict_types=1);

use Illuminate\Container\Container;
use Illuminate\Support\Arr;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenRevoked;

it('ships the same translation keys and placeholders in every language', function (string $file): void {
    $english = require __DIR__."/../../resources/lang/en/{$file}.php";
    $slovak = require __DIR__."/../../resources/lang/sk/{$file}.php";

    $placeholders = static fn (array $lines): array => array_map(
        static function (string $line): array {
            preg_match_all('/:[a-z_]+/', $line, $found);
            $found = array_unique($found[0]);
            sort($found);

            return $found;
        },
        Arr::dot($lines),
    );

    expect(array_keys(Arr::dot($slovak)))->toBe(array_keys(Arr::dot($english)))
        ->and($placeholders($slovak))->toBe($placeholders($english))
        ->and($english)->not->toBeEmpty();
})->with(['errors']);

it('translates the revoked-token message into Slovak', function (): void {
    app()->setLocale('sk');

    expect(TokenRevoked::forJti('jti-1')->getMessage())->toBe('Token bol odvolaný.')
        ->and(trans('jwt::errors.token_revoked'))->toBe('Token bol odvolaný.');

    app()->setLocale('en');

    expect(TokenRevoked::forJti('jti-1')->getMessage())->toBe('The token has been revoked.');
});

it('falls back to English without a translator', function (): void {
    $previous = Container::getInstance();
    Container::setInstance(new Container);

    try {
        expect(TokenRevoked::forJti('jti-1')->getMessage())->toBe('The token has been revoked.');
    } finally {
        Container::setInstance($previous);
    }
});

it('falls back to English when the line is missing', function (): void {
    app('translator')->setLoaded([]);
    app()->setLocale('xx');
    app('translator')->setFallback('xx');

    expect(TokenRevoked::forJti('jti-1')->getMessage())->toBe('The token has been revoked.');
});
