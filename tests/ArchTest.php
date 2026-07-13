<?php

declare(strict_types=1);

// Guard against any third-party JWT/crypto dependency by allow-listing only the
// permitted vendor roots (roundly + Laravel/Symfony runtime). Our own
// crypto-for-laravel is allowed — it owns the JOSE/signature/codec primitives —
// but any accidental `use` of a non-allowed vendor fails the suite.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt')
    ->toOnlyUse([
        'RoundlyConsulting\Jwt',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'Illuminate',
        'Carbon',
        'config',
        'config_path',
    ]);

arch('test support only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt\Tests')
    ->toOnlyUse(['RoundlyConsulting\Jwt', 'RoundlyConsulting\Crypto', 'Illuminate', 'Orchestra\Testbench']);

// Every cryptographic primitive comes from crypto-for-laravel — never a
// third-party JOSE/JWT library, and never a hand-rolled copy back inside this
// package. Signing, verification, HMAC and constant-time comparison must not be
// re-implemented here.
arch('no crypto primitive is re-implemented locally')
    ->expect('RoundlyConsulting\Jwt')
    ->not->toUse([
        'hash_hmac',
        'hash_equals',
        'openssl_sign',
        'openssl_verify',
        'openssl_pkey_new',
        'openssl_pkey_get_private',
        'openssl_pkey_get_public',
        'openssl_pkey_get_details',
        'base64_encode',
        'base64_decode',
    ]);

// Only crypto's PUBLIC surface is ours to use. `Signature\OpenSsl` is tagged
// `@internal` — the private-PEM export goes through `RsaKey::privatePem()` /
// `EcKey::privatePem()` instead, so an internal refactor of crypto can never
// break this package.
arch('never reaches into an internal crypto class')
    ->expect('RoundlyConsulting\Jwt')
    ->not->toUse(['RoundlyConsulting\Crypto\Signature\OpenSsl']);

// The same rule, but derived from crypto itself: whatever crypto tags `@internal`
// today or tomorrow, this package must not import it.
it('imports no crypto class tagged @internal', function (): void {
    $cryptoSrc = realpath(__DIR__.'/../vendor/roundly-consulting/crypto-for-laravel/src');

    expect($cryptoSrc)->toBeString();

    /** @var list<string> $internal */
    $internal = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $cryptoSrc, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        if (! str_contains($contents, '@internal')) {
            continue;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) === 1) {
            $internal[] = trim($namespace[1]).'\\'.$file->getBasename('.php');
        }
    }

    // Sanity: crypto really does tag something internal (guards a silent no-op).
    expect($internal)->not->toBeEmpty();

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(realpath(__DIR__.'/../src'), FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        foreach ($internal as $class) {
            expect($contents)->not->toContain($class, "{$file->getPathname()} imports the internal crypto class {$class}");
        }
    }
});

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\Jwt')
    ->toUseStrictTypes();

arch('exceptions live in an Exceptions namespace')
    ->expect('RoundlyConsulting\Jwt\Jose\Exceptions')
    ->toBeClasses();
