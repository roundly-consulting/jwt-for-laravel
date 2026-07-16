<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\UserTokens\TokenUser;
use RoundlyConsulting\Testing\Arch\ArchPresets;

// ── Shared presets ───────────────────────────────────────────────────────────

ArchPresets::strictTypes('RoundlyConsulting\Jwt');

// Two intentional extension points are exempt: TokenUser, which
// `jwt.guard.identity` invites a host to subclass (pinned by the preset below
// instead), and JwtException, the base every JOSE error extends so a host can
// catch token failures uniformly.
ArchPresets::finalByDefault('RoundlyConsulting\Jwt')
    ->ignoring([TokenUser::class, JwtException::class]);

ArchPresets::swappableModelsAreNotFinal([TokenUser::class => 'jwt.guard.identity']);

// Every cryptographic primitive comes from crypto-for-laravel — never a
// third-party JOSE/JWT library, and never a hand-rolled copy back inside this
// package. Signing, verification, HMAC and constant-time comparison must not be
// re-implemented here.
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Jwt');

ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');

ArchPresets::noDebuggingLeftovers();

// `modelsResolveThroughSeam` is deliberately NOT adopted: jwt ships no Eloquent
// model and no `*_model` config key, so its stray-literal half is inert here —
// and its late-static-binding half would forbid the `new static` in
// TokenUser::fromClaims() that is precisely what makes `jwt.guard.identity`
// honour a host swap (see tests/Feature/IdentitySwapTest.php).

// ── jwt-specific rules the presets don't express ─────────────────────────────

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
        'RoundlyConsulting\PackageToolkit',
        'Illuminate',
        'Carbon',
        'config',
    ]);

arch('test support only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt\Tests')
    ->toOnlyUse([
        'RoundlyConsulting\Jwt',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Testing',
        'Illuminate',
        'Orchestra\Testbench',
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

arch('exceptions live in an Exceptions namespace')
    ->expect('RoundlyConsulting\Jwt\Jose\Exceptions')
    ->toBeClasses();
