<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;
use RoundlyConsulting\Jwt\Support\KeyRepository;

it('loads and caches the private key', function (): void {
    $repository = new KeyRepository(fixturesDir().'/keys/jwt-private.pem', null);

    $first = $repository->privateKey();

    expect($first)->toBeInstanceOf(RsaPrivateKey::class)
        ->and($repository->privateKey())->toBe($first);
});

it('loads and caches the public key', function (): void {
    $repository = new KeyRepository(null, fixturesDir().'/keys/jwt-public.pem');

    $first = $repository->publicKey();

    expect($first)->toBeInstanceOf(RsaPublicKey::class)
        ->and($repository->publicKey())->toBe($first);
});

it('throws an actionable error when the private key is not configured', function (): void {
    (new KeyRepository(null, null))->privateKey();
})->throws(KeyLoadFailed::class, 'JWT_PRIVATE_KEY_PATH');

it('throws an actionable error when the public key is not configured', function (): void {
    (new KeyRepository(null, null))->publicKey();
})->throws(KeyLoadFailed::class, 'JWT_PUBLIC_KEY_PATH');

it('throws an actionable error when the private key file is missing', function (): void {
    (new KeyRepository('/no/such/private.pem', null))->privateKey();
})->throws(KeyLoadFailed::class, 'jwt:generate-keys');

it('throws an actionable error when the public key file is missing', function (): void {
    (new KeyRepository(null, '/no/such/public.pem'))->publicKey();
})->throws(KeyLoadFailed::class, 'jwt-public.pem');
