<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Crypto\Jose\ClaimMismatchException;
use RoundlyConsulting\Crypto\Jose\Claims as CryptoClaims;
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
     * A whole float (e.g. 1.0) is accepted; a fractional one, or a whole float
     * outside the 64-bit integer range (casting one wraps: 1e19 reads as a large
     * negative number, INF as 0), is not. The rules are crypto's, so the two
     * copies can't drift apart again.
     *
     * @throws ClaimMismatch when absent, not an integer, or outside the 64-bit integer range.
     */
    public function int(string $name): int
    {
        try {
            return (new CryptoClaims($this->claims))->int($name);
        } catch (ClaimMismatchException $e) {
            throw new ClaimMismatch($e->getMessage(), previous: $e);
        }
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
     * The OIDC `sid` claim, or null when the token carries none.
     *
     * @throws ClaimMismatch when present but not a string.
     */
    public function sessionId(): ?string
    {
        return $this->has('sid') ? $this->string('sid') : null;
    }

    /**
     * The RFC 8176 `amr` claim, or an empty list when the token carries none.
     *
     * @return list<string>
     *
     * @throws ClaimMismatch when present but not a list of strings.
     */
    public function authMethods(): array
    {
        return $this->has('amr') ? $this->list('amr') : [];
    }

    /**
     * The OIDC `auth_time` claim (unix seconds), or null when the token carries none.
     *
     * @throws ClaimMismatch when present but not an integer.
     */
    public function authTime(): ?int
    {
        return $this->has('auth_time') ? $this->int('auth_time') : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}
