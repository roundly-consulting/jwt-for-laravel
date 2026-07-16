<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests;

/**
 * A TestCase that enables claim-based authorization before the provider boots,
 * so the conditional `Gate::before` hook is actually registered.
 */
abstract class ClaimAuthorizationTestCase extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    protected function configBeforeBoot(): array
    {
        return ['jwt.authorize_from_claims' => true];
    }
}
