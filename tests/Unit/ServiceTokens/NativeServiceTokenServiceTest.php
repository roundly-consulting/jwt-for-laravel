<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\ServiceTokens\NativeServiceTokenService;

const SERVICE_SECRET = 'unit-test-service-secret-0123456789ab';

/**
 * @param  list<string>  $allowedIssuers
 * @param  array<string, string>  $secrets
 */
function serviceService(
    ?string $secret = SERVICE_SECRET,
    string $issuer = 'logger',
    ?string $defaultAudience = 'auth',
    array $allowedIssuers = [],
    string $serviceName = 'auth',
    array $secrets = [],
): NativeServiceTokenService {
    return new NativeServiceTokenService(
        new Encoder,
        new Decoder,
        $secret,
        $issuer,
        $defaultAudience,
        60,
        $allowedIssuers,
        $serviceName,
        0,
        null,
        $secrets,
    );
}

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('issues and verifies a service token', function (): void {
    $service = serviceService();
    $issued = $service->issue();

    $claims = $service->verify($issued->token);

    expect($claims->string('scope'))->toBe('service')
        ->and($claims->string('iss'))->toBe('logger')
        ->and($claims->string('aud'))->toBe('auth')
        ->and($issued->expiresAt->getTimestamp())->toBe(1_700_000_060);
});

it('honours an explicit audience over the default', function (): void {
    $issued = serviceService()->issue('billing');

    $target = serviceService(serviceName: 'billing');

    expect($target->verify($issued->token)->string('aud'))->toBe('billing');
});

it('rejects a token addressed to another service', function (): void {
    $issued = serviceService()->issue('auth');

    serviceService(serviceName: 'billing')->verify($issued->token);
})->throws(ClaimMismatch::class, 'audience');

it('accepts any issuer when the allow-list is empty', function (): void {
    $issued = serviceService(issuer: 'some-random-service')->issue();

    expect(serviceService()->verify($issued->token)->string('iss'))->toBe('some-random-service');
});

it('enforces a non-empty issuer allow-list', function (): void {
    $issued = serviceService(issuer: 'intruder')->issue();

    serviceService(allowedIssuers: ['logger', 'geo'])->verify($issued->token);
})->throws(ClaimMismatch::class, 'allow-listed');

it('accepts an allow-listed issuer', function (): void {
    $issued = serviceService(issuer: 'logger')->issue();

    expect(serviceService(allowedIssuers: ['logger'])->verify($issued->token)->string('iss'))
        ->toBe('logger');
});

it('raises a misconfiguration when issuing without a secret', function (): void {
    serviceService(secret: null)->issue();
})->throws(ServiceAuthMisconfigured::class);

it('raises a misconfiguration when verifying without a secret', function (): void {
    serviceService(secret: '')->verify('a.b.c');
})->throws(ServiceAuthMisconfigured::class);

it('rejects a token that is not scoped to service', function (): void {
    // Mint an HS256 token with the same secret but a different scope.
    $encoder = new Encoder;
    $token = $encoder->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'access',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(SERVICE_SECRET), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'scope');

it('rejects a service token with an empty issuer', function (): void {
    $token = (new Encoder)->encode([
        'iss' => '',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(SERVICE_SECRET), Algorithm::HS256);

    serviceService()->verify($token);
})->throws(ClaimMismatch::class, 'issuer is missing');

it('raises a misconfiguration for a too-short shared secret, never a 401', function (): void {
    serviceService(secret: 'short')->issue();
})->throws(ServiceAuthMisconfigured::class, 'at least 32 random bytes');

it('raises a misconfiguration when issuing without any audience', function (): void {
    serviceService(defaultAudience: null)->issue();
})->throws(ServiceAuthMisconfigured::class, 'audience');

it('raises a misconfiguration when issuing with an empty issuer', function (): void {
    serviceService(issuer: '')->issue();
})->throws(ServiceAuthMisconfigured::class, 'JWT_SERVICE_ISSUER');

it('raises a misconfiguration when verifying with no service name', function (): void {
    serviceService(serviceName: '')->verify('a.b.c');
})->throws(ServiceAuthMisconfigured::class, 'JWT_SERVICE_NAME');

const ISSUER_SECRETS = [
    'logger' => 'per-issuer-secret-for-logger-0123456789',
    'geo' => 'per-issuer-secret-for-geo-0123456789abc',
];

it('issues and verifies with per-issuer secrets', function (): void {
    $issued = serviceService(issuer: 'logger', secrets: ISSUER_SECRETS)->issue();

    $claims = serviceService(secrets: ISSUER_SECRETS)->verify($issued->token);

    expect($claims->string('iss'))->toBe('logger');
});

it('rejects a token whose iss claims another issuer secret', function (): void {
    // Signed with geo's secret but claiming to be logger: the iss selects
    // logger's secret, whose signature cannot match.
    $token = (new Encoder)->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(ISSUER_SECRETS['geo']), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

it('rejects an unknown issuer as an invalid signature, not an enumeration oracle', function (): void {
    // An unknown `iss` burns a full HMAC verification against a fixed dummy
    // secret and fails as InvalidSignature — identical to a known issuer with a
    // bad signature — so the configured issuer set can't be probed.
    $token = (new Encoder)->encode([
        'iss' => 'intruder',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(SERVICE_SECRET), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

// The constant the unknown-issuer path used to burn its HMAC with. It sits in the
// public source, so anyone could sign a token with it and pass verification.
const OLD_UNKNOWN_ISSUER_BURN_SECRET = 'jwt-for-laravel/unknown-issuer/constant-time-burn/8f3c1a9e2b';

/**
 * @param  array<string, mixed>  $claims
 */
function forgedServiceToken(string $secret, array $claims = []): string
{
    return (new Encoder)->encode([
        'iss' => 'attacker',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_300,
        'permissions' => ['*'],
        ...$claims,
    ], HmacSecret::fromString($secret), Algorithm::HS256);
}

it('rejects an unknown issuer signed with the old public burn secret', function (): void {
    $service = serviceService(secret: null, secrets: ['billing' => ISSUER_SECRETS['logger']]);

    $service->verify(forgedServiceToken(OLD_UNKNOWN_ISSUER_BURN_SECRET));
})->throws(InvalidSignature::class, 'HS256 signature verification failed.');

it('rejects an allow-listed issuer that has no secret in the map', function (): void {
    $service = serviceService(
        secret: null,
        allowedIssuers: ['billing', 'ghost'],
        secrets: ['billing' => ISSUER_SECRETS['logger']],
    );

    $service->verify(forgedServiceToken(OLD_UNKNOWN_ISSUER_BURN_SECRET, ['iss' => 'ghost']));
})->throws(InvalidSignature::class, 'HS256 signature verification failed.');

it('never accepts an unknown issuer, even when its signature verifies against the burn key', function (): void {
    $service = serviceService(secret: null, secrets: ['billing' => ISSUER_SECRETS['logger']]);

    // Second layer: even a token signed with this instance's own burn key — which
    // never leaves the object — is refused once the issuer turned out unknown.
    $burn = (new ReflectionProperty($service, 'unknownIssuerSecret'))->getValue($service);

    $service->verify(forgedServiceToken($burn));
})->throws(InvalidSignature::class, 'HS256 signature verification failed.');

it('burns an unknown issuer with a per-instance random key, never a constant', function (): void {
    $burn = fn (NativeServiceTokenService $service): mixed => (new ReflectionProperty($service, 'unknownIssuerSecret'))->getValue($service);

    $first = $burn(serviceService(secrets: ISSUER_SECRETS));
    $second = $burn(serviceService(secrets: ISSUER_SECRETS));

    expect($first)->toBeString()->toHaveLength(64)
        ->and($second)->toBeString()->toHaveLength(64)
        ->and($first)->not->toBe($second)
        ->and((new ReflectionClass(NativeServiceTokenService::class))->getConstants())
        ->not->toContain(OLD_UNKNOWN_ISSUER_BURN_SECRET);
});

it('ignores the shared secret when per-issuer secrets are configured', function (): void {
    // Signed with the shared secret while per-issuer mode is active — must fail.
    $token = (new Encoder)->encode([
        'iss' => 'logger',
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(SERVICE_SECRET), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(InvalidSignature::class);

it('raises a misconfiguration when the own issuer is absent from the secret map', function (): void {
    serviceService(issuer: 'unmapped', secrets: ISSUER_SECRETS)->issue();
})->throws(ServiceAuthMisconfigured::class, 'own issuer');

it('rejects an oversized bearer string before decoding', function (): void {
    $oversized = str_repeat('a', 9000).'.b.c';

    serviceService()->verify($oversized);
})->throws(MalformedToken::class, 'maximum permitted length');

// Per-issuer mode reads `iss` from the unverified payload purely to select the
// secret — a `kid` lookup. Malformed input must fail structurally, never select
// a secret from garbage.
it('rejects a malformed bearer string in per-issuer mode', function (string $token, string $reason): void {
    expect(fn () => serviceService(secrets: ISSUER_SECRETS)->verify($token))
        ->toThrow(MalformedToken::class, $reason);
})->with([
    'two segments' => ['a.b', 'exactly three segments'],
    'payload is not base64url' => ['aGVhZGVy.not+base64url.c', 'not valid base64url'],
    'payload is not json' => ['aGVhZGVy.bm90LWpzb24.c', 'not valid JSON'],
]);

it('rejects a token with no issuer in per-issuer mode', function (): void {
    $token = (new Encoder)->encode([
        'aud' => 'auth',
        'scope' => 'service',
        'exp' => 1_700_000_060,
    ], HmacSecret::fromString(SERVICE_SECRET), Algorithm::HS256);

    serviceService(secrets: ISSUER_SECRETS)->verify($token);
})->throws(ClaimMismatch::class, 'issuer is missing');

it('carries caller-defined claims into the token', function (): void {
    $service = serviceService();

    // A token handed to a subprocess that then acts on its holder's behalf cannot
    // take its authorization from a request body — anything the subject can write
    // is by definition not an authorization. So it rides in the token.
    $claims = $service->verify($service->issue('auth', ['execution' => 'exec-1', 'send_external' => true])->token);

    expect($claims->get('execution'))->toBe('exec-1')
        ->and($claims->get('send_external'))->toBeTrue();
});

it('refuses to let a caller supply a registered claim', function (): void {
    // Merging instead of refusing would let a caller move `aud` and address any
    // service in the mesh — and silently ignoring it would leave the caller
    // believing it did something.
    expect(fn () => serviceService()->issue('auth', ['aud' => 'somewhere-else']))
        ->toThrow(ServiceAuthMisconfigured::class);
});

it('refuses a caller that tries to name a person or their permissions', function (string $claim): void {
    // Not just the registered JWT claims: `sub` is the name a future "service acting
    // for a user" feature reaches for, and `permissions`/`tv`/`email` are what
    // `TokenUser::fromClaims` reads — so a token asserting its own permissions that
    // some consumer later hydrates into a TokenUser is exactly this guard's purpose.
    expect(fn () => serviceService()->issue('auth', [$claim => 'anything']))
        ->toThrow(ServiceAuthMisconfigured::class);
})->with(['sub', 'permissions', 'tv', 'email', 'email_verified']);

it('is callable through the interface with a named argument', function (): void {
    // The implementation used to name the parameter `$extraClaims` while the
    // interface declared `$claims`, so `issue(claims: [...])` against the interface
    // fatalled on the concrete class.
    $issuer = serviceService();

    expect($issuer->verify($issuer->issue(audience: 'auth', claims: ['company' => 'acme'])->token)->get('company'))
        ->toBe('acme');
});
