<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\UserTokens\Scope;

it('backs the canonical wire scope strings', function (): void {
    expect(Scope::Access->value)->toBe('access')
        ->and(Scope::TwoFaPending->value)->toBe('2fa_pending')
        ->and(Scope::EmailVerify->value)->toBe('email_verify')
        ->and(Scope::Service->value)->toBe('service');
});

it('exposes the enum helpers from enums-for-laravel', function (): void {
    expect(Scope::values()->all())->toBe(['access', '2fa_pending', 'email_verify', 'service'])
        ->and(Scope::tryFrom('access'))->toBe(Scope::Access)
        ->and(Scope::tryFrom('nope'))->toBeNull();
});
