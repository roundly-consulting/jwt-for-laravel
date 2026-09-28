<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

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
    RsaKey::private((string) file_get_contents($this->private));
    RsaKey::public((string) file_get_contents($this->public));
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

/*
 * The README's install step, against the SHIPPED config (no JWT_* env): the
 * private key path used to default to null, so `jwt:generate-keys` refused to run
 * until the host invented a path.
 */
it('generates keys the app then signs and verifies with, under the shipped config', function (): void {
    app()->useStoragePath($this->dir);
    config(['jwt' => require __DIR__.'/../../config/jwt.php']);
    config(['jwt.issuer' => 'jwt-issuer', 'jwt.audience' => 'web']);

    Artisan::call('about', ['--only' => 'jwt']);
    expect(Artisan::output())->toMatch('/Signing key\W+MISSING/');

    $this->artisan('jwt:generate-keys')->assertSuccessful();

    $private = $this->dir.'/jwt-private.key';
    $public = $this->dir.'/jwt-public.pem';

    expect(is_file($private))->toBeTrue()
        ->and(is_file($public))->toBeTrue()
        ->and(substr(sprintf('%o', fileperms($private)), -4))->toBe('0600');

    Artisan::call('about', ['--only' => 'jwt']);
    $about = Artisan::output();

    expect($about)->toMatch('/Signing key\W+SET/')
        ->and($about)->toMatch('/Verification key\W+SET/');

    $token = Jwt::mintAccessToken(AccessTokenRequest::for('user-1'))->token;
    expect(Jwt::verify($token)->string('sub'))->toBe('user-1');

    unlink($private);
});
