<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\UserTokens\Scopes;

it('exposes the canonical wire scope strings', function (): void {
    expect(Scopes::ACCESS)->toBe('access')
        ->and(Scopes::TWO_FA_PENDING)->toBe('2fa_pending')
        ->and(Scopes::EMAIL_VERIFY)->toBe('email_verify')
        ->and(Scopes::SERVICE)->toBe('service');
});
