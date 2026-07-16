<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Jwt\JwtServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /**
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [CryptoServiceProvider::class, JwtServiceProvider::class];
    }
}
