<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Algorithm;

it('has exactly the two supported algorithms', function (): void {
    expect(Algorithm::values()->all())->toBe(['RS256', 'HS256']);
});

it('knows which algorithm is asymmetric', function (): void {
    expect(Algorithm::RS256->isAsymmetric())->toBeTrue()
        ->and(Algorithm::HS256->isAsymmetric())->toBeFalse();
});

it('adopts the enums-for-laravel helpers', function (): void {
    expect(Algorithm::tryFromName('RS256'))->toBe(Algorithm::RS256)
        ->and(Algorithm::tryFromName('nope'))->toBeNull()
        ->and(Algorithm::count())->toBe(2)
        ->and(Algorithm::names()->all())->toBe(['RS256', 'HS256']);
});
