<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Support;

use Illuminate\Support\Str;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\PackageToolkit\Support\Config;
use SensitiveParameter;

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
     * empty string, not null); a value that is not a string at all throws. Never
     * for a secret — read those through {@see self::optionalSecret()}.
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
     * A secret setting (`jwt.service.secret`, `jwt.service.secrets`), read like
     * {@see self::optionalString()} — null when absent or blank, a string as given —
     * but never exposed when it is not a string: the value is a sensitive
     * parameter here and in {@see JwtMisconfigured::invalidSecretValue()}, so a
     * trace never carries it, and the message names only its type.
     *
     * @throws JwtMisconfigured
     */
    public static function optionalSecret(string $key, #[SensitiveParameter] mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw JwtMisconfigured::invalidSecretValue($key, 'a string or null', $value);
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
     * This service's own name — the `aud` inbound service tokens must carry, and
     * the default `iss` of the ones it mints: `jwt.service.name`, else a host's
     * `app.service` (not a stock Laravel key, but services that define it keep
     * their identity), else a slug of `app.name`. '' when none can be derived, so
     * verification fails closed instead of pinning nothing. A `jwt.service.name`
     * that is not a string throws rather than silently re-pinning to `app.name`.
     *
     * @throws JwtMisconfigured
     */
    public static function serviceName(mixed $name, mixed $appService, mixed $appName): string
    {
        foreach ([self::optionalString('jwt.service.name', $name), $appService] as $value) {
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        return is_string($appName) ? Str::slug($appName) : '';
    }

    /**
     * Parses the `SERVICE_JWT_SECRETS` per-issuer map: a comma-separated list
     * of `issuer:secret` pairs (null or blank = per-issuer mode off). A malformed
     * pair throws rather than being dropped: dropping every pair would quietly
     * fall back to the shared `secret`, unbinding each issuer from its own key.
     * An issuer named twice throws too, rather than letting the last pair win.
     * The raw value is a sensitive parameter, so a trace never carries it.
     *
     * @return array<string, string>
     *
     * @throws JwtMisconfigured
     */
    public static function secretMap(#[SensitiveParameter] mixed $value): array
    {
        $value = self::optionalSecret('jwt.service.secrets', $value);

        if ($value === null) {
            return [];
        }

        $map = [];
        $positions = [];

        foreach (explode(',', $value) as $index => $pair) {
            // Trim both sides so `billing: s3cret` doesn't derive a different
            // HMAC key from a stray space, and a padded issuer still matches.
            [$issuer, $secret] = str_contains($pair, ':') ? array_map(trim(...), explode(':', $pair, 2)) : ['', ''];

            if ($issuer === '' || $secret === '') {
                throw JwtMisconfigured::malformedSecretPair();
            }

            // Last-wins would silently drop one secret for that issuer: a
            // rendering bug, so refuse it like any other malformed map.
            if (array_key_exists($issuer, $positions)) {
                throw JwtMisconfigured::duplicateSecretIssuer($issuer, $positions[$issuer], $index + 1);
            }

            $positions[$issuer] = $index + 1;
            $map[$issuer] = $secret;
        }

        return $map;
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
