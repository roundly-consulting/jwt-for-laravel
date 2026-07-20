<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

/**
 * Resolves a configured key path to an absolute filesystem path.
 *
 * Key paths are conventionally configured relative to the application root
 * (`storage/keys/jwt-private.pem`). Resolving them against the *current working
 * directory* would make key loading depend on where the process was started —
 * an artisan command run from the project root would find the key while the
 * same app served by a web server, a queue worker, or a dev script started from
 * a parent directory would not. Anchoring to `base_path()` makes the location
 * stable regardless of CWD, and keeps the writer (`jwt:generate-keys`) and the
 * reader ({@see KeyRepository}) pointed at the same file.
 *
 * The base path is passed in rather than read from a global helper, so this
 * stays a pure function. Absolute paths are returned untouched.
 */
final class KeyPath
{
    public static function resolve(string $path, string $basePath): string
    {
        if ($path === '' || self::isAbsolute($path)) {
            return $path;
        }

        return rtrim($basePath, '/\\').DIRECTORY_SEPARATOR.$path;
    }

    private static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, DIRECTORY_SEPARATOR)
            || preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1;
    }
}
