<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\PackageToolkit\Support\Config;

/**
 * Strict readers for the package's non-boolean settings. A key that is not set —
 * absent, null or blank (`''` or whitespace, what a host's `KEY=` gives) — takes its
 * default; a present value of the wrong shape throws {@see JwtMisconfigured} naming
 * the key — `'five'` never becomes a 0-second TTL, and a mistyped list or class
 * never silently widens what the package accepts.
 *
 * Callers read the value with a literal `config()` themselves and hand it in, so the
 * key stays visible to the config contract.
 *
 * @internal the package's own config wiring — hosts configure `config/jwt.php`.
 */
final class Settings
{
    /**
     * An int or a canonical integer string (env values arrive as strings), bounded
     * by `$min`; `$default` when `$value` is not set (null or blank).
     *
     * @throws JwtMisconfigured
     */
    public static function integer(string $key, mixed $value, int $default, ?int $min = null): int
    {
        return Config::for([$key => $value], JwtMisconfigured::class)->integer($key, $default, $min);
    }

    /**
     * An optional string: null when absent or blank (`JWT_KID=` in a .env is an
     * empty string, not null); a value that is not a string at all throws.
     *
     * @throws JwtMisconfigured
     */
    public static function optionalString(string $key, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw JwtMisconfigured::invalidValue($key, 'a string or null', $value);
        }

        return trim($value) === '' ? null : $value;
    }

    /**
     * A required string: `$default` when `$value` is not set (null or blank); a
     * non-string value throws instead of silently reading as the default.
     *
     * @throws JwtMisconfigured
     */
    public static function string(string $key, mixed $value, string $default): string
    {
        if (self::notSet($value)) {
            return $default;
        }

        if (! is_string($value)) {
            throw JwtMisconfigured::invalidValue($key, 'a string', $value);
        }

        return $value;
    }

    /**
     * A list of non-empty strings (each trimmed); `[]` when not set (null or blank). A
     * non-array, or an entry that is not a non-empty string, throws — a mistyped
     * allow-list must never read as the empty "allow anything" list.
     *
     * @return list<string>
     *
     * @throws JwtMisconfigured
     */
    public static function stringList(string $key, mixed $value): array
    {
        if (self::notSet($value)) {
            return [];
        }

        if (! is_array($value)) {
            throw JwtMisconfigured::invalidValue($key, 'a list of strings', $value);
        }

        $strings = [];

        foreach ($value as $item) {
            if (! is_string($item) || trim($item) === '') {
                throw JwtMisconfigured::invalidValue($key, 'a list of non-empty strings', $value);
            }

            $strings[] = trim($item);
        }

        return $strings;
    }

    /**
     * Absent, null or blank (`''` or whitespace): the key is not set, so its default
     * applies — a host's `KEY=` means the same as leaving the key out.
     */
    public static function notSet(mixed $value): bool
    {
        return $value === null || (is_string($value) && trim($value) === '');
    }
}
