<?php

declare(strict_types=1);

// Guard against any third-party JWT/crypto dependency by allow-listing only the
// permitted vendor roots (roundly + Laravel/Symfony runtime). Any accidental
// `use` of a non-allowed vendor fails the suite — without naming competitors.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt')
    ->toOnlyUse(['RoundlyConsulting\Jwt', 'RoundlyConsulting\Enums', 'Illuminate', 'Carbon', 'config', 'config_path']);

arch('test support only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt\Tests')
    ->toOnlyUse(['RoundlyConsulting\Jwt', 'Illuminate', 'Orchestra\Testbench']);

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\Jwt')
    ->toUseStrictTypes();

arch('exceptions live in an Exceptions namespace')
    ->expect('RoundlyConsulting\Jwt\Jose\Exceptions')
    ->toBeClasses();
