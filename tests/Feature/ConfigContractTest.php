<?php

declare(strict_types=1);

it('ships exactly the config keys it reads', function (): void {
    expect(realpath(__DIR__.'/../../config/jwt.php'))
        ->toSatisfyConfigContract(realpath(__DIR__.'/../../src'));
});
