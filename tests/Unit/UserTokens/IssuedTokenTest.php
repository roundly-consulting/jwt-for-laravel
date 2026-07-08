<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

it('exposes its token, expiry and jti', function (): void {
    $expiresAt = CarbonImmutable::createFromTimestamp(1_700_000_900);
    $token = new IssuedToken('a.b.c', $expiresAt, 'jti-1');

    expect($token->token)->toBe('a.b.c')
        ->and($token->expiresAt)->toBe($expiresAt)
        ->and($token->jti)->toBe('jti-1');
});
