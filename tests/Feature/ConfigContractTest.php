<?php

declare(strict_types=1);

/**
 * `jwt.authorize_from_claims` is read through the toolkit's strict reader
 * (`Config::using(JwtMisconfigured::class)->boolean(...)`), which the scraper
 * does not follow, so that literal counts as a read.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(realpath(__DIR__.'/../../config/jwt.php'))
        ->toSatisfyConfigContract(realpath(__DIR__.'/../../src'), [
            'extraReadPrefixes' => ['jwt.authorize_from_claims'],
        ]);
});
