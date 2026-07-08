<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\ServiceTokens\ServiceIdentity;

it('uses the calling service iss as its identifier', function (): void {
    $claims = new Claims(['iss' => 'cosmos-logger', 'scope' => 'service']);
    $identity = ServiceIdentity::fromClaims($claims);

    expect($identity->getAuthIdentifier())->toBe('cosmos-logger')
        ->and($identity->getAuthIdentifierName())->toBe('iss')
        ->and($identity->claims())->toBe($claims);
});

it('is a stateless identity', function (): void {
    $identity = ServiceIdentity::fromClaims(new Claims(['iss' => 'cosmos-logger']));
    $identity->setRememberToken('ignored');

    expect($identity->getAuthPassword())->toBe('')
        ->and($identity->getAuthPasswordName())->toBe('password')
        ->and($identity->getRememberToken())->toBe('')
        ->and($identity->getRememberTokenName())->toBe('');
});
