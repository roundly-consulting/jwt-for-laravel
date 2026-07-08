<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\KeyLoadFailed;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;

it('loads a valid RSA public key', function (): void {
    expect(RsaPublicKey::fromPem(publicKeyPem())->key)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
});

it('loads a valid RSA private key', function (): void {
    expect(RsaPrivateKey::fromPem(privateKeyPem())->key)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
});

it('rejects an unreadable public PEM', function (): void {
    RsaPublicKey::fromPem('not a pem');
})->throws(KeyLoadFailed::class);

it('rejects an unreadable private PEM', function (): void {
    RsaPrivateKey::fromPem('not a pem');
})->throws(KeyLoadFailed::class);

it('rejects an undersized RSA public key', function (): void {
    RsaPublicKey::fromPem(readFixture('keys/weak-1024-public.pem'));
})->throws(KeyLoadFailed::class, 'minimum of 2048');

it('rejects an undersized RSA private key', function (): void {
    RsaPrivateKey::fromPem(readFixture('keys/weak-1024.pem'));
})->throws(KeyLoadFailed::class, 'minimum of 2048');

it('rejects a non-RSA public key', function (): void {
    RsaPublicKey::fromPem(readFixture('keys/ec-public.pem'));
})->throws(KeyLoadFailed::class, 'not an RSA key');

it('rejects a non-RSA private key', function (): void {
    RsaPrivateKey::fromPem(readFixture('keys/ec-private.pem'));
})->throws(KeyLoadFailed::class, 'not an RSA key');
