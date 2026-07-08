<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use RoundlyConsulting\Jwt\JwtServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [JwtServiceProvider::class];
    }

    protected function fixturePath(string $path): string
    {
        return __DIR__.'/Fixtures/'.ltrim($path, '/');
    }

    protected function fixture(string $path): string
    {
        $contents = file_get_contents($this->fixturePath($path));

        if ($contents === false) {
            throw new \RuntimeException("Missing fixture: {$path}");
        }

        return $contents;
    }
}
