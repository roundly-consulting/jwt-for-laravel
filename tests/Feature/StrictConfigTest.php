<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\JwtServiceProvider;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\Support\Settings;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

/**
 * Regression (strict config sweep): the shipped config cast both switches with
 * `(bool) env(...)`, so `JWT_CHECK_DENYLIST=off` read as true and a typo such as
 * `JWT_AUTHORIZE_FROM_CLAIMS=disabled` silently switched claim authorization ON.
 * The config file now hands the raw env string to the strict reader.
 */
dataset('jwt env switches', [
    'JWT_CHECK_DENYLIST' => ['JWT_CHECK_DENYLIST'],
    'JWT_AUTHORIZE_FROM_CLAIMS' => ['JWT_AUTHORIZE_FROM_CLAIMS'],
]);

/**
 * @return array<string, mixed>
 */
function shippedJwtConfig(string $env, string $value): array
{
    $_SERVER[$env] = $value;

    try {
        /** @var array<string, mixed> $config */
        $config = require __DIR__.'/../../config/jwt.php';
    } finally {
        unset($_SERVER[$env]);
    }

    return $config;
}

it('hands the raw env string to the strict reader (strict config)', function (string $env): void {
    $config = shippedJwtConfig($env, 'disabled');

    $value = $env === 'JWT_CHECK_DENYLIST' ? $config['guard']['check_denylist'] : $config['authorize_from_claims'];

    expect($value)->toBe('disabled');
})->with('jwt env switches');

it('keeps the shipped switch defaults as real booleans', function (): void {
    /** @var array{guard: array{check_denylist: mixed}, authorize_from_claims: mixed} $config */
    $config = require __DIR__.'/../../config/jwt.php';

    expect($config['guard']['check_denylist'])->toBeTrue()
        ->and($config['authorize_from_claims'])->toBeFalse();
});

it('reads an env-style "off" denylist switch from the shipped config as off', function (): void {
    config(['jwt.guard.check_denylist' => shippedJwtConfig('JWT_CHECK_DENYLIST', 'off')['guard']['check_denylist']]);

    Artisan::call('about --only=jwt');

    expect(Artisan::output())->toMatch('/Denylist check\s*\.*\s*OFF/');
});

it('reads a blank switch in the about section as its default (strict config)', function (): void {
    config(['jwt.guard.check_denylist' => '', 'jwt.authorize_from_claims' => ' ']);

    Artisan::call('about --only=jwt');

    expect(Artisan::output())->toMatch('/Denylist check\s*\.*\s*ON/')
        ->toMatch('/Claim authorization\s*\.*\s*OFF/');
});

it('refuses a typo in the claim authorization switch when the provider boots (strict config)', function (): void {
    config(['jwt.authorize_from_claims' => 'disabled']);

    $provider = new JwtServiceProvider($this->app);

    expect(fn () => (fn () => $this->registerClaimAuthorization())->call($provider))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [jwt.authorize_from_claims] must be a boolean (true/false, 1/0, on/off or yes/no), [disabled] given.');
});

it('refuses a typo in either switch in the about section (strict config)', function (string $key): void {
    config([$key => 'disabled']);

    expect(fn () => Artisan::call('about --only=jwt'))->toThrow(JwtMisconfigured::class, "[{$key}]");
})->with(['jwt.guard.check_denylist', 'jwt.authorize_from_claims']);

it('hands raw env integers to the strict reader (strict config)', function (string $env, string $path): void {
    $config = shippedJwtConfig($env, 'five');

    expect(data_get($config, $path))->toBe('five');
})->with([
    'JWT_TTL' => ['JWT_TTL', 'ttl'],
    'JWT_CHALLENGE_TTL' => ['JWT_CHALLENGE_TTL', 'challenge_ttl'],
    'JWT_VERIFY_TTL' => ['JWT_VERIFY_TTL', 'verify_ttl'],
    'JWT_LEEWAY' => ['JWT_LEEWAY', 'leeway'],
    'SERVICE_JWT_TTL' => ['SERVICE_JWT_TTL', 'service.ttl'],
]);

it('refuses a junk or out-of-range integer instead of reading it as 0 (strict config)', function (string $key, mixed $junk, string $service): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.denylist.store' => 'array',
        $key => $junk,
    ]);

    expect(fn () => app($service))->toThrow(JwtMisconfigured::class, "Configuration value [{$key}]");
})->with([
    'ttl word' => ['jwt.ttl', 'five', UserTokenIssuer::class],
    'ttl zero' => ['jwt.ttl', 0, UserTokenIssuer::class],
    'challenge ttl float string' => ['jwt.challenge_ttl', '1.5', UserTokenIssuer::class],
    'leeway junk' => ['jwt.leeway', '10s', UserTokenVerifier::class],
    'leeway negative' => ['jwt.leeway', -1, UserTokenVerifier::class],
    'denylist leeway junk' => ['jwt.leeway', 'ten', Denylist::class],
    'service ttl junk' => ['jwt.service.ttl', 'a minute', NativeServiceTokenService::class],
]);

it('reads a blank integer as not set, so the shipped default applies (strict config)', function (string $blank): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.denylist.store' => 'array',
        'jwt.ttl' => $blank,
        'jwt.challenge_ttl' => $blank,
        'jwt.verify_ttl' => $blank,
        'jwt.leeway' => $blank,
        'jwt.service.ttl' => $blank,
    ]);

    expect(app(UserTokenIssuer::class))->toBeInstanceOf(UserTokenIssuer::class)
        ->and(app(UserTokenVerifier::class))->toBeInstanceOf(UserTokenVerifier::class)
        ->and(app(Denylist::class))->toBeInstanceOf(Denylist::class)
        ->and(app(NativeServiceTokenService::class))->toBeInstanceOf(NativeServiceTokenService::class);
})->with(['empty' => [''], 'whitespace' => ['  ']]);

it('uses the shipped defaults for absent integers (strict config)', function (): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.ttl' => null,
        'jwt.challenge_ttl' => null,
        'jwt.verify_ttl' => null,
        'jwt.leeway' => '0',
    ]);

    expect(app(UserTokenIssuer::class))->toBeInstanceOf(UserTokenIssuer::class)
        ->and(app(UserTokenVerifier::class))->toBeInstanceOf(UserTokenVerifier::class);
});

it('refuses a mistyped string or list setting instead of using the default (strict config)', function (string $key, mixed $junk, string $service): void {
    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.service.secret' => 'unit-test-service-secret-0123456789ab',
        'jwt.denylist.store' => 'array',
        $key => $junk,
    ]);

    expect(fn () => app($service))->toThrow(JwtMisconfigured::class, "Configuration value [{$key}]");
})->with([
    'issuers not a list' => ['jwt.service.issuers', 'billing,api', NativeServiceTokenService::class],
    'issuers non-string entry' => ['jwt.service.issuers', ['billing', 42], NativeServiceTokenService::class],
    'issuers blank entry' => ['jwt.service.issuers', ['billing', ' '], NativeServiceTokenService::class],
    'denylist prefix not a string' => ['jwt.denylist.prefix', ['jwt:'], Denylist::class],
    'denylist store not a string' => ['jwt.denylist.store', ['redis'], Denylist::class],
    'kid not a string' => ['jwt.kid', 7, KeyRepository::class],
    'key path not a string' => ['jwt.public_key_path', ['a.pem'], KeyRepository::class],
    'issuer not a string' => ['jwt.issuer', ['iss'], UserTokenIssuer::class],
    'service name not a string' => ['jwt.service.name', ['svc'], NativeServiceTokenService::class],
    'service secret not a string' => ['jwt.service.secret', 123, NativeServiceTokenService::class],
]);

/**
 * Regression (1.1.1 follow-up): a published config file can hold any PHP value,
 * and a non-string secret setting reached the strict reader and its exception
 * factory as a plain argument. Wherever `zend.exception_ignore_args` is off the
 * trace then carried the raw value (error trackers and debug pages show frame
 * arguments), and an int secret was even echoed in the message. The cases are
 * looped, not a dataset, so the test's own arguments stay out of the trace.
 */
it('keeps a non-string secret setting out of the message and the trace (strict config)', function (): void {
    $canary = 'leak-canary-secret-0123456789abcdefghijklmnopqrstuv';
    $number = 4815162342424242;

    $cases = [
        ['jwt.service.secrets', ['billing' => $canary], 'array', 'leak-canary'],
        ['jwt.service.secrets', ["billing:{$canary}"], 'array', 'leak-canary'],
        ['jwt.service.secrets', $number, 'int', (string) $number],
        ['jwt.service.secret', [$canary], 'array', 'leak-canary'],
        ['jwt.service.secret', ['primary' => ['nested' => $canary]], 'array', 'leak-canary'],
        ['jwt.service.secret', $number, 'int', (string) $number],
    ];

    // Everything a renderer or error tracker can show: the message, the string
    // forms, and every scalar among the frames' arguments — for the whole chain.
    // An object argument renders as its class name, a SensitiveParameterValue too.
    $exposed = static function (Throwable $e): string {
        $seen = [];
        $collect = static function (mixed $value) use (&$collect, &$seen): void {
            if (is_array($value)) {
                foreach ($value as $index => $item) {
                    $seen[] = (string) $index;
                    $collect($item);
                }
            } elseif (is_scalar($value)) {
                $seen[] = (string) $value;
            }
        };

        for ($current = $e; $current !== null; $current = $current->getPrevious()) {
            $seen[] = $current->getMessage();
            $seen[] = $current->getTraceAsString();
            $seen[] = (string) $current;

            foreach ($current->getTrace() as $frame) {
                $collect($frame['args'] ?? []);
            }
        }

        return implode("\n", $seen);
    };

    // A dev-style ini: call arguments kept in the trace, strings not cut at 15 bytes.
    $ignoreArgs = ini_set('zend.exception_ignore_args', '0');
    $maxLength = ini_set('zend.exception_string_param_max_len', '1000000');

    try {
        foreach ($cases as [$key, $value, $type, $marker]) {
            app()->forgetInstance(NativeServiceTokenService::class);
            config(['jwt.service.secret' => null, 'jwt.service.secrets' => null, $key => $value]);

            expect(fn () => app(NativeServiceTokenService::class))
                ->toThrow(function (JwtMisconfigured $e) use ($key, $type, $marker, $exposed): void {
                    expect($e->getMessage())->toBe("Configuration value [{$key}] must be a string or null, {$type} given.")
                        // The key is a frame argument too: proves the trace kept its arguments.
                        ->and($exposed($e))->toContain("\n{$key}\n")->not->toContain($marker);
                });
        }
    } finally {
        ini_set('zend.exception_ignore_args', (string) $ignoreArgs);
        ini_set('zend.exception_string_param_max_len', (string) $maxLength);
    }
});

it('reads a secret setting like an optional string (strict config)', function (): void {
    expect(Settings::optionalSecret('jwt.service.secret', null))->toBeNull()
        ->and(Settings::optionalSecret('jwt.service.secret', ' '))->toBeNull()
        // Never trimmed: a secret keeps every character.
        ->and(Settings::optionalSecret('jwt.service.secret', ' padded-secret '))->toBe(' padded-secret ')
        ->and(fn () => Settings::optionalSecret('jwt.service.secret', true))
        ->toThrow(JwtMisconfigured::class, 'Configuration value [jwt.service.secret] must be a string or null, bool given.');
});

it('reads a blank string or list setting as not set, so the default applies (strict config)', function (): void {
    expect(Settings::string('jwt.denylist.prefix', '', 'jwt:denylist:'))->toBe('jwt:denylist:')
        ->and(Settings::string('jwt.denylist.prefix', '  ', 'jwt:denylist:'))->toBe('jwt:denylist:')
        ->and(Settings::string('jwt.denylist.prefix', 'app:jwt:', 'jwt:denylist:'))->toBe('app:jwt:')
        ->and(Settings::stringList('jwt.service.issuers', ''))->toBe([])
        ->and(Settings::stringList('jwt.service.issuers', null))->toBe([])
        ->and(Settings::optionalString('jwt.kid', ' '))->toBeNull();

    config([
        'jwt.denylist.store' => 'array',
        'jwt.denylist.prefix' => '',
    ]);

    expect(app(Denylist::class))->toBeInstanceOf(Denylist::class);
});
