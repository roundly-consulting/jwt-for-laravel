<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\Support\KeyRepository;

it('loads and caches the private key', function (): void {
    $repository = new KeyRepository(fixturesDir().'/keys/jwt-private.pem', null);

    $first = $repository->privateKey();

    expect($first)->toBeInstanceOf(RsaKey::class)
        ->and($repository->privateKey())->toBe($first);
});

it('loads and caches the public key', function (): void {
    $repository = new KeyRepository(null, fixturesDir().'/keys/jwt-public.pem');

    $first = $repository->publicKey();

    expect($first)->toBeInstanceOf(RsaKey::class)
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

// The PEM guards live in crypto-for-laravel; every rejection must still reach the
// host as this package's own KeyLoadFailed, never a raw CryptoException.
it('rejects a file that is not a PEM as a key-load failure', function (): void {
    // An existing file whose contents OpenSSL cannot parse as a key.
    (new KeyRepository(null, fixturesDir().'/tokens/manifest.php'))->publicKey();
})->throws(KeyLoadFailed::class, 'unusable');

it('rejects an unreadable private PEM as a key-load failure', function (): void {
    (new KeyRepository(fixturesDir().'/tokens/manifest.php', null))->privateKey();
})->throws(KeyLoadFailed::class, 'unusable');

it('rejects an undersized RSA key', function (string $file, string $method): void {
    $repository = $method === 'privateKey'
        ? new KeyRepository(fixturesDir().'/keys/'.$file, null)
        : new KeyRepository(null, fixturesDir().'/keys/'.$file);

    $repository->{$method}();
})->with([
    'private' => ['weak-1024.pem', 'privateKey'],
    'public' => ['weak-1024-public.pem', 'publicKey'],
])->throws(KeyLoadFailed::class, 'minimum of 2048');

it('rejects a non-RSA key', function (string $file, string $method): void {
    $repository = $method === 'privateKey'
        ? new KeyRepository(fixturesDir().'/keys/'.$file, null)
        : new KeyRepository(null, fixturesDir().'/keys/'.$file);

    $repository->{$method}();
})->with([
    'private' => ['ec-private.pem', 'privateKey'],
    'public' => ['ec-public.pem', 'publicKey'],
])->throws(KeyLoadFailed::class, 'not an RSA key');
