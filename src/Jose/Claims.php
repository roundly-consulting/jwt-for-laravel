<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;

/**
 * An immutable bag of decoded JWT claims with typed, validating accessors.
 *
 * The decoder produces a `Claims` instance only after the signature and
 * temporal checks pass, so consumers can read claims without re-validating the
 * token itself.
 */
final readonly class Claims
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(private array $claims) {}

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    public function get(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    /**
     * @throws ClaimMismatch when the claim is absent.
     */
    public function require(string $name): mixed
    {
        if (! $this->has($name)) {
            throw new ClaimMismatch("Required claim [{$name}] is missing.");
        }

        return $this->claims[$name];
    }

    /**
     * @throws ClaimMismatch when absent or not a string.
     */
    public function string(string $name): string
    {
        $value = $this->require($name);

        if (! is_string($value)) {
            throw new ClaimMismatch("Claim [{$name}] is not a string.");
        }

        return $value;
    }

    /**
     * @throws ClaimMismatch when absent or not an integer.
     */
    public function int(string $name): int
    {
        $value = $this->require($name);

        // JSON numbers decode to int|float; a whole float (e.g. 1.0) is fine,
        // a fractional timestamp is not.
        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) && floor($value) === $value) {
            return (int) $value;
        }

        throw new ClaimMismatch("Claim [{$name}] is not an integer.");
    }

    /**
     * @return list<string>
     *
     * @throws ClaimMismatch when absent or not a list of strings.
     */
    public function list(string $name): array
    {
        $value = $this->require($name);

        if (! is_array($value) || ! array_is_list($value)) {
            throw new ClaimMismatch("Claim [{$name}] is not a list.");
        }

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new ClaimMismatch("Claim [{$name}] must be a list of strings.");
            }
        }

        /** @var list<string> $value */
        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}
