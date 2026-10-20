<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * A user provider that looks a user up loosely, the way a database coerces a string
 * to an integer: "007" finds user 7. It hands back whatever identifier it was built
 * with, so a test can make that identifier a non-scalar too.
 */
final class LooseUserProvider implements UserProvider
{
    public function __construct(private readonly mixed $identifier = null) {}

    public function retrieveById($identifier): ?Authenticatable
    {
        $id = (int) $identifier;

        return $id === 0 ? null : new GenericUser(['id' => $this->identifier ?? $id]);
    }

    public function retrieveByToken($identifier, $token): ?Authenticatable
    {
        return null;
    }

    public function updateRememberToken(Authenticatable $user, $token): void {}

    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        return null;
    }

    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        return false;
    }

    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void {}
}
