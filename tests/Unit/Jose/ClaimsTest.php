<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;

function claims(array $data = []): Claims
{
    return new Claims($data);
}

it('reads present and absent claims', function (): void {
    $claims = claims(['sub' => 'user-1']);

    expect($claims->has('sub'))->toBeTrue()
        ->and($claims->has('missing'))->toBeFalse()
        ->and($claims->get('sub'))->toBe('user-1')
        ->and($claims->get('missing'))->toBeNull();
});

it('requires a present claim', function (): void {
    expect(claims(['a' => 1])->require('a'))->toBe(1);
});

it('throws when requiring a missing claim', function (): void {
    claims()->require('sub');
})->throws(ClaimMismatch::class);

it('returns a typed string', function (): void {
    expect(claims(['iss' => 'issuer'])->string('iss'))->toBe('issuer');
});

it('rejects a non-string for string()', function (): void {
    claims(['iss' => 123])->string('iss');
})->throws(ClaimMismatch::class);

it('returns a typed int and coerces whole floats', function (): void {
    expect(claims(['exp' => 100])->int('exp'))->toBe(100)
        ->and(claims(['exp' => 100.0])->int('exp'))->toBe(100);
});

it('rejects a fractional number for int()', function (): void {
    claims(['exp' => 100.5])->int('exp');
})->throws(ClaimMismatch::class);

it('rejects a non-number for int()', function (): void {
    claims(['exp' => 'soon'])->int('exp');
})->throws(ClaimMismatch::class);

it('returns a list of strings', function (): void {
    expect(claims(['permissions' => ['a', 'b']])->list('permissions'))->toBe(['a', 'b']);
});

it('rejects a non-list for list()', function (): void {
    claims(['permissions' => ['a' => 1]])->list('permissions');
})->throws(ClaimMismatch::class);

it('rejects a list containing non-strings', function (): void {
    claims(['permissions' => ['a', 2]])->list('permissions');
})->throws(ClaimMismatch::class);

it('exposes all claims', function (): void {
    expect(claims(['a' => 1, 'b' => 2])->all())->toBe(['a' => 1, 'b' => 2]);
});
