<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Testing;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Jwt\ServiceTokens\Services;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

/**
 * The `services()` sub-accessor under `Jwt::fake()`: every issue — directly or
 * through `request()` / `authenticate()` — runs for real and is recorded.
 */
final readonly class RecordingServices extends Services
{
    public function __construct(
        private JwtFake $fake,
        Container $container,
    ) {
        parent::__construct($container);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function issue(?string $audience = null, array $claims = []): IssuedToken
    {
        $issued = parent::issue($audience, $claims);

        $this->fake->recordServiceToken($issued);

        return $issued;
    }
}
