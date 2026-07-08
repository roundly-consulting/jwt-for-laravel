<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\Jose\Keys\HmacSecret;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPrivateKey;
use RoundlyConsulting\Jwt\Jose\Keys\RsaPublicKey;
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

function rsaPrivateKey(): RsaPrivateKey
{
    return RsaPrivateKey::fromPem(privateKeyPem());
}

function rsaPublicKey(): RsaPublicKey
{
    return RsaPublicKey::fromPem(publicKeyPem());
}

function hmacSecret(string $value = 'test-hmac-secret-value-0123456789ab'): HmacSecret
{
    return new HmacSecret($value);
}

/**
 * @return array{hmac_secret: string, tokens: array<string, array<string, mixed>>}
 */
function manifest(): array
{
    return require fixturesDir().'/tokens/manifest.php';
}

/**
 * Named datasets, one per committed static parity token.
 *
 * @return array<string, array{0: string, 1: array<string, mixed>}>
 */
function manifestCases(): array
{
    $cases = [];

    foreach (manifest()['tokens'] as $file => $meta) {
        $cases[$file] = [$file, $meta];
    }

    return $cases;
}
