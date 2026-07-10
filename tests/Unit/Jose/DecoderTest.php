<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Jwt\Jose\Algorithm;
use RoundlyConsulting\Jwt\Jose\Base64Url;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\AlgorithmMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenExpired;
use RoundlyConsulting\Jwt\Jose\Exceptions\TokenNotYetValid;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedCriticalHeader;
use RoundlyConsulting\Jwt\Jose\Exceptions\UnexpectedTokenType;

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));
    $this->encoder = new Encoder;
    $this->decoder = new Decoder;
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function rs256(array $claims): string
{
    return (new Encoder)->encode($claims, rsaPrivateKey(), Algorithm::RS256);
}

function futureExp(): int
{
    return CarbonImmutable::now()->getTimestamp() + 900;
}

/**
 * Craft a raw compact JWS from explicit header/payload/signature parts.
 */
function craft(array $header, array $payload, string $signature = 'sig'): string
{
    return Base64Url::encode(json_encode($header)).'.'
        .Base64Url::encode(json_encode($payload)).'.'
        .Base64Url::encode($signature);
}

/**
 * Sign a compact RS256 JWS over an explicit header (so `typ` can be varied)
 * with the fixture private key — the header the Encoder would never emit.
 */
function rs256WithHeader(array $header, array $payload): string
{
    $input = Base64Url::encode(json_encode($header)).'.'.Base64Url::encode(json_encode($payload));
    $signature = '';
    openssl_sign($input, $signature, rsaPrivateKey()->key, OPENSSL_ALGO_SHA256);

    return $input.'.'.Base64Url::encode($signature);
}

it('verifies a valid RS256 token and returns claims', function (): void {
    $token = rs256(['sub' => 'user-1', 'exp' => futureExp()]);

    $claims = $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);

    expect($claims->string('sub'))->toBe('user-1');
});

it('verifies a valid HS256 token', function (): void {
    $token = $this->encoder->encode(['exp' => futureExp()], hmacSecret(), Algorithm::HS256);

    $claims = $this->decoder->decode($token, hmacSecret(), Algorithm::HS256, 0);

    expect($claims->int('exp'))->toBe(futureExp());
});

it('rejects a token with the wrong number of segments', function (): void {
    $this->decoder->decode('a.b', rsaPublicKey(), Algorithm::RS256, 0);
})->throws(MalformedToken::class);

it('rejects a tampered payload', function (): void {
    $token = rs256(['sub' => 'user-1', 'exp' => futureExp()]);
    [$h, , $s] = explode('.', $token);
    $forged = $h.'.'.Base64Url::encode('{"sub":"admin","exp":'.futureExp().'}').'.'.$s;

    $this->decoder->decode($forged, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(InvalidSignature::class);

it('rejects a flipped signature byte', function (): void {
    $token = $this->encoder->encode(['exp' => futureExp()], hmacSecret(), Algorithm::HS256);
    [$h, $p] = explode('.', $token);

    $this->decoder->decode($h.'.'.$p.'.'.Base64Url::encode('tampered'), hmacSecret(), Algorithm::HS256, 0);
})->throws(InvalidSignature::class);

it('rejects the alg:none downgrade', function (string $none): void {
    $token = craft(['typ' => 'JWT', 'alg' => $none], ['exp' => futureExp()], '');

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->with(['none', 'None', 'NONE'])->throws(AlgorithmMismatch::class);

it('rejects a header alg that differs from the pinned algorithm', function (): void {
    // Signed correctly as HS256 but the verifier is pinned to RS256.
    $token = $this->encoder->encode(['exp' => futureExp()], hmacSecret(), Algorithm::HS256);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(AlgorithmMismatch::class);

it('rejects a crit header', function (): void {
    $token = craft(['typ' => 'JWT', 'alg' => 'RS256', 'crit' => ['exp']], ['exp' => futureExp()]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(UnexpectedCriticalHeader::class);

it('rejects a token whose typ is not JWT (RFC 8725 explicit typing)', function (string $typ): void {
    $token = craft(['typ' => $typ, 'alg' => 'RS256'], ['exp' => futureExp()]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->with(['at+jwt', 'dpop+jwt', 'not-a-jwt', ''])->throws(UnexpectedTokenType::class);

it('rejects a non-string typ header', function (): void {
    $token = craft(['typ' => ['JWT'], 'alg' => 'RS256'], ['exp' => futureExp()]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(UnexpectedTokenType::class);

it('accepts JWT typ case-insensitively and the application/jwt media type', function (string $typ): void {
    $signed = rs256WithHeader(['typ' => $typ, 'alg' => 'RS256'], ['sub' => 'a', 'exp' => futureExp()]);

    expect($this->decoder->decode($signed, rsaPublicKey(), Algorithm::RS256, 0)->string('sub'))->toBe('a');
})->with(['JWT', 'jwt', 'application/jwt', 'application/JWT']);

it('accepts a token with no typ header for interop', function (): void {
    $signed = rs256WithHeader(['alg' => 'RS256'], ['sub' => 'a', 'exp' => futureExp()]);

    expect($this->decoder->decode($signed, rsaPublicKey(), Algorithm::RS256, 0)->string('sub'))->toBe('a');
});

it('rejects a token longer than the maximum permitted length', function (): void {
    $token = rs256(['sub' => 'a', 'exp' => futureExp(), 'bloat' => str_repeat('x', 9000)]);

    expect(strlen($token))->toBeGreaterThan(8192);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(MalformedToken::class, 'maximum permitted length');

it('rejects an RS256 verifier handed an HMAC secret', function (): void {
    $token = rs256(['exp' => futureExp()]);

    $this->decoder->decode($token, hmacSecret(), Algorithm::RS256, 0);
})->throws(AlgorithmMismatch::class);

it('rejects an HS256 verifier handed an RSA public key', function (): void {
    $token = $this->encoder->encode(['exp' => futureExp()], hmacSecret(), Algorithm::HS256);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::HS256, 0);
})->throws(AlgorithmMismatch::class);

it('rejects an expired token', function (): void {
    $token = rs256(['exp' => CarbonImmutable::now()->getTimestamp() - 100]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(TokenExpired::class);

it('accepts an expired token within leeway', function (): void {
    $token = rs256(['sub' => 'a', 'exp' => CarbonImmutable::now()->getTimestamp() - 5]);

    $claims = $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 10);

    expect($claims->string('sub'))->toBe('a');
});

it('rejects a token whose nbf is in the future', function (): void {
    $token = rs256(['exp' => futureExp(), 'nbf' => CarbonImmutable::now()->getTimestamp() + 100]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(TokenNotYetValid::class);

it('accepts a nbf within leeway', function (): void {
    $token = rs256(['sub' => 'a', 'exp' => futureExp(), 'nbf' => CarbonImmutable::now()->getTimestamp() + 5]);

    expect($this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 10)->string('sub'))->toBe('a');
});

it('rejects a token issued in the future (iat)', function (): void {
    $token = rs256(['exp' => futureExp(), 'iat' => CarbonImmutable::now()->getTimestamp() + 100]);

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(TokenNotYetValid::class);

it('rejects a token with no exp', function (): void {
    $this->decoder->decode(rs256(['sub' => 'a']), rsaPublicKey(), Algorithm::RS256, 0);
})->throws(ClaimMismatch::class);

it('rejects a non-integer exp', function (): void {
    $this->decoder->decode(rs256(['exp' => 'soon']), rsaPublicKey(), Algorithm::RS256, 0);
})->throws(ClaimMismatch::class);

it('rejects a header that is not a JSON object', function (): void {
    $token = Base64Url::encode('"astring"').'.'.Base64Url::encode('{"exp":1}').'.'.Base64Url::encode('sig');

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(MalformedToken::class);

it('rejects a payload that is a JSON array', function (): void {
    $token = Base64Url::encode('{"typ":"JWT","alg":"RS256"}').'.'.Base64Url::encode('[1,2,3]').'.'.Base64Url::encode('sig');

    $this->decoder->decode($token, rsaPublicKey(), Algorithm::RS256, 0);
})->throws(MalformedToken::class);
