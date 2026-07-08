<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;

beforeEach(function (): void {
    $this->dir = sys_get_temp_dir().'/jwt-keys-'.uniqid();
    $this->private = $this->dir.'/jwt-private.pem';
    $this->public = $this->dir.'/jwt-public.pem';

    config([
        'jwt.private_key_path' => $this->private,
        'jwt.public_key_path' => $this->public,
    ]);
});

afterEach(function (): void {
    foreach ([$this->private, $this->public] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }

    if (is_dir($this->dir)) {
        rmdir($this->dir);
    }
});

it('generates a usable 2048-bit RSA keypair', function (): void {
    $this->artisan('jwt:generate-keys')->assertSuccessful();

    expect(is_file($this->private))->toBeTrue()
        ->and(is_file($this->public))->toBeTrue();

    // The keys parse as a valid RSA pair of the required size.
    RsaPrivateKey::fromPem((string) file_get_contents($this->private));
    RsaPublicKey::fromPem((string) file_get_contents($this->public));
});

it('writes the private key with 0600 permissions', function (): void {
    $this->artisan('jwt:generate-keys')->assertSuccessful();

    expect(substr(sprintf('%o', fileperms($this->private)), -4))->toBe('0600');
});

it('refuses to overwrite existing keys without --force', function (): void {
    $this->artisan('jwt:generate-keys')->assertSuccessful();
    $original = file_get_contents($this->private);

    $this->artisan('jwt:generate-keys')->assertFailed();

    expect(file_get_contents($this->private))->toBe($original);
});

it('overwrites existing keys with --force', function (): void {
    $this->artisan('jwt:generate-keys')->assertSuccessful();
    $original = file_get_contents($this->private);

    $this->artisan('jwt:generate-keys --force')->assertSuccessful();

    expect(file_get_contents($this->private))->not->toBe($original);
});

it('fails when no private key path is configured', function (): void {
    config(['jwt.private_key_path' => null]);

    $this->artisan('jwt:generate-keys')->assertFailed();
});

it('fails when no public key path is configured', function (): void {
    config(['jwt.public_key_path' => null]);

    $this->artisan('jwt:generate-keys')->assertFailed();
});
