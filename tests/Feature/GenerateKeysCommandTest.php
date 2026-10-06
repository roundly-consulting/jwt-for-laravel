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
    removeKeyDirectory($this->dir);
});

/**
 * Deletes a key directory, restoring the permissions a test took away first.
 */
function removeKeyDirectory(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }

    chmod($dir, 0755);

    foreach (array_diff((array) scandir($dir), ['.', '..']) as $entry) {
        $path = $dir.'/'.$entry;

        if (is_dir($path)) {
            removeKeyDirectory($path);
        } else {
            chmod($path, 0644);
            unlink($path);
        }
    }

    rmdir($dir);
}

/**
 * @return list<string>
 */
function keyDirectoryEntries(string $dir): array
{
    return array_values(array_diff((array) scandir($dir), ['.', '..']));
}

function runningAsRoot(): bool
{
    return function_exists('posix_geteuid') && posix_geteuid() === 0;
}

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

/*
 * The private key used to be touch()ed with umask permissions (often 0644) and
 * chmod()ed to 0600 only afterwards: another local process could open it in that
 * window and keep the handle. A second process polls the mode during a real run.
 */
it('never exposes the private key path with group or other permission bits', function (): void {
    $stop = $this->dir.'.stop';
    $poller = <<<'PHP'
        [, $path, $stop] = $argv;
        $seen = [];
        $deadline = microtime(true) + 60;
        fwrite(STDOUT, "ready\n");
        do {
            $stopped = file_exists($stop) || microtime(true) >= $deadline;
            clearstatcache(true, $path);
            $perms = @fileperms($path);
            if ($perms !== false) {
                $seen[sprintf('%o', $perms & 0777)] = true;
            }
        } while (! $stopped);
        fwrite(STDOUT, implode(',', array_keys($seen)));
        PHP;

    $process = proc_open([PHP_BINARY, '-r', $poller, $this->private, $stop], [1 => ['pipe', 'w']], $pipes);
    expect($process)->not->toBeFalse();
    fgets($pipes[1]);

    try {
        $this->artisan('jwt:generate-keys')->assertSuccessful()->run();
    } finally {
        touch($stop);
        $modes = trim((string) stream_get_contents($pipes[1]));
        proc_close($process);
        unlink($stop);
    }

    expect(explode(',', $modes))->toBe(['600']);
});

it('replaces the private key with a new file, so a handle held on the old one never sees the new key', function (): void {
    $this->artisan('jwt:generate-keys')->assertSuccessful()->run();
    $original = (string) file_get_contents($this->private);
    $inode = fileinode($this->private);
    $held = fopen($this->private, 'r');

    $this->artisan('jwt:generate-keys --force')->assertSuccessful()->run();

    rewind($held);
    $seenThroughHandle = stream_get_contents($held);
    fclose($held);
    clearstatcache();

    expect($seenThroughHandle)->toBe($original)
        ->and(fileinode($this->private))->not->toBe($inode)
        ->and(file_get_contents($this->private))->not->toBe($original)
        ->and(substr(sprintf('%o', fileperms($this->private)), -4))->toBe('0600')
        ->and(substr(sprintf('%o', fileperms($this->public)), -4))->toBe('0644')
        ->and(keyDirectoryEntries($this->dir))->toBe(['jwt-private.pem', 'jwt-public.pem']);
});

/*
 * `--force` used to overwrite the private key before writing the public one, so a
 * public write that failed left a new private key next to the old public key:
 * every token minted afterwards failed verification.
 */
it('leaves the existing private key untouched when the public key cannot be written', function (Closure $breakPublic): void {
    $this->public = $this->dir.'/public/jwt-public.pem';
    config(['jwt.public_key_path' => $this->public]);

    $this->artisan('jwt:generate-keys')->assertSuccessful()->run();
    $private = (string) file_get_contents($this->private);
    $public = (string) file_get_contents($this->public);

    $breakPublic($this->public);

    $this->artisan('jwt:generate-keys --force')
        ->expectsOutputToContain($this->public)
        ->assertFailed()
        ->run();

    // The private key is byte-identical, and no temp file is left in either directory.
    expect(file_get_contents($this->private))->toBe($private)
        ->and(keyDirectoryEntries($this->dir))->toBe(['jwt-private.pem', 'public']);

    if (is_file($this->public)) {
        expect(file_get_contents($this->public))->toBe($public)
            ->and(keyDirectoryEntries(dirname($this->public)))->toBe(['jwt-public.pem']);
    }
})->with([
    'read-only public key' => function (string $path): void {
        chmod($path, 0444);
    },
    'read-only public key in a read-only directory' => function (string $path): void {
        chmod($path, 0444);
        chmod(dirname($path), 0555);
    },
    'read-only directory without the public key' => function (string $path): void {
        unlink($path);
        chmod(dirname($path), 0555);
    },
    'a directory at the public key path' => function (string $path): void {
        unlink($path);
        mkdir($path);
    },
])->skip(fn (): bool => runningAsRoot(), 'root writes through read-only permissions');

/*
 * The error branches relied on touch()/file_put_contents() returning false, but
 * Laravel turns their warnings into an ErrorException first: the operator got a
 * stack trace instead of the command's own message and FAILURE.
 */
it('fails with its own message when the key directory is not writable', function (): void {
    mkdir($this->dir, 0555);

    $this->artisan('jwt:generate-keys')
        ->expectsOutputToContain('Unable to create')
        ->assertFailed()
        ->run();

    expect(keyDirectoryEntries($this->dir))->toBe([]);
})->skip(fn (): bool => runningAsRoot(), 'root writes through read-only permissions');

it('fails with its own message when the key directory cannot be created', function (): void {
    mkdir($this->dir, 0555);
    $this->private = $this->dir.'/nested/jwt-private.pem';
    config(['jwt.private_key_path' => $this->private]);

    $this->artisan('jwt:generate-keys')
        ->expectsOutputToContain('Unable to create the directory')
        ->assertFailed()
        ->run();

    expect(keyDirectoryEntries($this->dir))->toBe([]);
})->skip(fn (): bool => runningAsRoot(), 'root writes through read-only permissions');

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

it('fails when no private key path is configured', function (mixed $unset): void {
    config(['jwt.private_key_path' => $unset]);

    $this->artisan('jwt:generate-keys')->assertFailed();
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('fails when no public key path is configured', function (mixed $unset): void {
    config(['jwt.public_key_path' => $unset]);

    $this->artisan('jwt:generate-keys')->assertFailed();
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

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
