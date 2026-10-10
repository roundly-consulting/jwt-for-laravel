<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Tests\ClaimAuthorizationTestCase;
use RoundlyConsulting\Jwt\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature', 'ArchTest.php');
uses(ClaimAuthorizationTestCase::class)->in('ClaimAuthorization');

function fixturesDir(): string
{
    return __DIR__.'/Fixtures';
}

function readFixture(string $relative): string
{
    $contents = file_get_contents(fixturesDir().'/'.ltrim($relative, '/'));

    if ($contents === false) {
        throw new RuntimeException("Missing fixture: {$relative}");
    }

    return $contents;
}

function privateKeyPem(): string
{
    return readFixture('keys/jwt-private.pem');
}

function publicKeyPem(): string
{
    return readFixture('keys/jwt-public.pem');
}

function rsaPrivateKey(): RsaKey
{
    return RsaKey::private(privateKeyPem());
}

function rsaPublicKey(): RsaKey
{
    return RsaKey::public(publicKeyPem());
}

function hmacSecret(string $value = 'test-hmac-secret-value-0123456789ab'): HmacSecret
{
    return HmacSecret::fromString($value);
}

/**
 * @return array{hmac_secret: string, service_secrets: string, tokens: array<string, array<string, mixed>>}
 */
function manifest(): array
{
    return require fixturesDir().'/tokens/manifest.php';
}

/**
 * Named datasets, one per committed static parity token: all of them, or only
 * the per-issuer (`issuer:<name>`) or only the other entries.
 *
 * @return array<string, array{0: string, 1: array<string, mixed>}>
 */
function manifestCases(?bool $perIssuer = null): array
{
    $cases = [];

    foreach (manifest()['tokens'] as $file => $meta) {
        if ($perIssuer === null || str_starts_with((string) $meta['key'], 'issuer:') === $perIssuer) {
            $cases[$file] = [$file, $meta];
        }
    }

    return $cases;
}

/**
 * The HMAC secret a manifest entry was signed with: the shared `hmac_secret`
 * (`hmac`), or one entry of the padded `service_secrets` map (`issuer:<name>`).
 */
function manifestHmacSecret(string $key): HmacSecret
{
    if (! str_starts_with($key, 'issuer:')) {
        return HmacSecret::fromString(manifest()['hmac_secret']);
    }

    foreach (explode(',', manifest()['service_secrets']) as $pair) {
        [$issuer, $secret] = array_map(trim(...), explode(':', $pair, 2));

        if ($issuer === substr($key, strlen('issuer:'))) {
            return HmacSecret::fromString($secret);
        }
    }

    throw new RuntimeException("No service secret for manifest key: {$key}");
}
