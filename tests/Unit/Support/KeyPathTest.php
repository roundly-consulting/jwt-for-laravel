<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Support\KeyPath;

it('anchors a relative path to the application root', function (): void {
    expect(KeyPath::resolve('storage/keys/jwt-private.pem', '/srv/app'))
        ->toBe('/srv/app'.DIRECTORY_SEPARATOR.'storage/keys/jwt-private.pem');
});

it('does not depend on the current working directory', function (): void {
    // The regression this guards: resolving against CWD meant `jwt:generate-keys`
    // run from the project root wrote a key the app could not find when served
    // from a parent directory (a dev script, a queue worker, a web server).
    $cwdBefore = getcwd();

    $fromRoot = KeyPath::resolve('storage/keys/jwt-private.pem', '/srv/app');
    chdir(sys_get_temp_dir());
    $fromTemp = KeyPath::resolve('storage/keys/jwt-private.pem', '/srv/app');

    if (is_string($cwdBefore)) {
        chdir($cwdBefore);
    }

    expect($fromTemp)->toBe($fromRoot);
});

it('returns absolute paths untouched', function (string $path): void {
    expect(KeyPath::resolve($path, '/srv/app'))->toBe($path);
})->with([
    '/etc/cosmos/jwt-private.pem',
    'C:\\keys\\jwt-private.pem',
    'C:/keys/jwt-private.pem',
]);

it('leaves an empty path empty so "not configured" stays distinguishable', function (): void {
    expect(KeyPath::resolve('', '/srv/app'))->toBe('');
});

it('does not double up separators when the base path has a trailing slash', function (): void {
    expect(KeyPath::resolve('storage/keys/k.pem', '/srv/app/'))
        ->toBe('/srv/app'.DIRECTORY_SEPARATOR.'storage/keys/k.pem');
});
