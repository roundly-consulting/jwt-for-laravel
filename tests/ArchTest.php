<?php

declare(strict_types=1);

arch('src never depends on a third-party JWT library')
    ->expect('RoundlyConsulting\Jwt')
    ->not->toUse(['Firebase\JWT', 'Firebase', 'Cron']);

arch('tests never depend on a third-party JWT library')
    ->expect('RoundlyConsulting\Jwt\Tests')
    ->not->toUse(['Firebase\JWT', 'Firebase', 'Cron']);

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\Jwt')
    ->toUseStrictTypes();

arch('exceptions live in an Exceptions namespace')
    ->expect('RoundlyConsulting\Jwt\Jose\Exceptions')
    ->toBeClasses();
