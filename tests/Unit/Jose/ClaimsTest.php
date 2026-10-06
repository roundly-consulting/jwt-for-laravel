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

// A JSON number too big for an int decodes as a float, and casting one past the
// range wraps (1e19 → -8446744073709551616, INF → 0), so a forged `tv` could
// match a user's token version.
it('rejects a whole float outside the 64-bit integer range for int()', function (float $value): void {
    expect(fn () => claims(['tv' => $value])->int('tv'))
        ->toThrow(ClaimMismatch::class, 'Claim [tv] is not an integer within the 64-bit integer range.');
})->with([
    'INF' => [INF],
    '-INF' => [-INF],
    '2^64' => [18446744073709551616.0],
    '2^63' => [9223372036854775808.0],
    '1e19' => [1e19],
    '-1e19' => [-1e19],
    'json 1e400' => [json_decode('1e400')],
]);

it('keeps the in-range edges of int()', function (): void {
    expect(claims(['tv' => -9223372036854775808.0])->int('tv'))->toBe(PHP_INT_MIN)
        ->and(claims(['tv' => 1.0])->int('tv'))->toBe(1);
});

it('rejects NaN for int()', function (): void {
    claims(['tv' => NAN])->int('tv');
})->throws(ClaimMismatch::class, 'Claim [tv] is not an integer.');

it('keeps the missing-claim message for int()', function (): void {
    claims([])->int('tv');
})->throws(ClaimMismatch::class, 'Required claim [tv] is missing.');

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

it('reads the OIDC session claims when present', function (): void {
    $claims = claims(['sid' => 'family-1', 'amr' => ['pwd', 'otp'], 'auth_time' => 1_700_000_000]);

    expect($claims->sessionId())->toBe('family-1')
        ->and($claims->authMethods())->toBe(['pwd', 'otp'])
        ->and($claims->authTime())->toBe(1_700_000_000);
});

it('reads absent OIDC session claims as null or empty', function (): void {
    expect(claims()->sessionId())->toBeNull()
        ->and(claims()->authMethods())->toBe([])
        ->and(claims()->authTime())->toBeNull();
});

it('rejects mistyped OIDC session claims', function (array $data, string $reader): void {
    claims($data)->{$reader}();
})->with([
    'sid not a string' => [['sid' => 42], 'sessionId'],
    'amr not a list' => [['amr' => 'pwd'], 'authMethods'],
    'amr not strings' => [['amr' => ['pwd', 1]], 'authMethods'],
    'auth_time not an int' => [['auth_time' => '1700000000'], 'authTime'],
])->throws(ClaimMismatch::class);
