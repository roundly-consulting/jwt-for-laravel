<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\PackageToolkit\Support\Config;

/**
 * Strict readers for the package's non-boolean settings. An absent (null) key takes
 * its default; a present value of the wrong shape throws {@see JwtMisconfigured}
 * naming the key — `'five'` never becomes a 0-second TTL, and a mistyped list or
 * class never silently widens what the package accepts.
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
     * by `$min`; `$default` only when `$value` is null.
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
     * A required string: `$default` only when `$value` is null; a blank or
     * non-string value throws instead of silently reading as the default.
     *
     * @throws JwtMisconfigured
     */
    public static function string(string $key, mixed $value, string $default): string
    {
        $value ??= $default;

        if (! is_string($value) || trim($value) === '') {
            throw JwtMisconfigured::invalidValue($key, 'a non-empty string', $value);
        }

        return $value;
    }

    /**
     * A list of non-empty strings (each trimmed); `[]` when absent. A non-array, or an
     * entry that is not a non-empty string, throws — a mistyped allow-list must never
     * read as the empty "allow anything" list.
     *
     * @return list<string>
     *
     * @throws JwtMisconfigured
     */
    public static function stringList(string $key, mixed $value): array
    {
        if ($value === null) {
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
}
