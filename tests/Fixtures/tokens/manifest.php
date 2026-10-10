<?php

declare(strict_types=1);

/**
 * Metadata for the committed static parity tokens under this directory.
 *
 * Each token string was generated once, out-of-band, from the committed test
 * keypair (tests/fixtures/keys) and the fixed HMAC secret below, then frozen
 * here verbatim. The parity suite freezes the clock to each entry's `verify_now`
 * and asserts the native Decoder's verdict matches `outcome` — proving the
 * decoder agrees with pre-captured tokens without ever running another JWT
 * library. The `claims` are the exact minted payload so the encode-parity test
 * can reproduce each token byte-for-byte.
 *
 * The RS256 tokens are verified with tests/fixtures/keys/jwt-public.pem; the
 * shared-secret HS256 token (`key` = `hmac`) with `hmac_secret` below.
 *
 * The per-issuer tokens (`key` = `issuer:<name>`, the map entry that SIGNED the
 * token) belong to `service_secrets`, the raw `SERVICE_JWT_SECRETS` string in its
 * padded form, so a port must trim exactly as the provider does to verify them.
 * `forged_issuer_service.jwt` claims `iss=logger` but is signed with geo's entry:
 * the `forged` outcome is the verdict of a receiver that selects the secret by
 * `iss`, which must refuse it with an invalid signature.
 */
return [
    'hmac_secret' => 'static-parity-service-secret-0123456789',

    'service_secrets' => 'logger : per-issuer-parity-secret-for-logger-0123456789 ,  geo:per-issuer-parity-secret-for-geo-0123456789abcdef',

    'tokens' => [
        'valid_access.jwt' => [
            'alg' => 'RS256',
            'key' => 'rsa',
            'verify_now' => 1700000000,
            'outcome' => 'valid',
            'scope' => 'access',
            'claims' => [
                'iss' => 'jwt-issuer',
                'aud' => 'web',
                'sub' => 'user-1',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000900,
                'jti' => '11111111-1111-4111-8111-111111111111',
                'scope' => 'access',
                'email' => 'a@b.test',
                'email_verified' => true,
                'tv' => 1,
                'permissions' => ['posts.view'],
            ],
        ],

        'expired_access.jwt' => [
            'alg' => 'RS256',
            'key' => 'rsa',
            'verify_now' => 1700002000,
            'outcome' => 'expired',
            'scope' => 'access',
            'claims' => [
                'iss' => 'jwt-issuer',
                'aud' => 'web',
                'sub' => 'user-1',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000900,
                'jti' => '11111111-1111-4111-8111-111111111111',
                'scope' => 'access',
            ],
        ],

        'twofa_pending.jwt' => [
            'alg' => 'RS256',
            'key' => 'rsa',
            'verify_now' => 1700000000,
            'outcome' => 'valid',
            'scope' => '2fa_pending',
            'claims' => [
                'iss' => 'jwt-issuer',
                'aud' => 'web',
                'sub' => 'user-1',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000900,
                'jti' => '11111111-1111-4111-8111-111111111111',
                'scope' => '2fa_pending',
            ],
        ],

        'valid_service.jwt' => [
            'alg' => 'HS256',
            'key' => 'hmac',
            'verify_now' => 1700000000,
            'outcome' => 'valid',
            'scope' => 'service',
            'claims' => [
                'iss' => 'logger',
                'aud' => 'auth',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000060,
                'jti' => '22222222-2222-4222-8222-222222222222',
                'scope' => 'service',
            ],
        ],

        'per_issuer_service.jwt' => [
            'alg' => 'HS256',
            'key' => 'issuer:logger',
            'verify_now' => 1700000000,
            'outcome' => 'valid',
            'scope' => 'service',
            'claims' => [
                'iss' => 'logger',
                'aud' => 'auth',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000060,
                'jti' => '33333333-3333-4333-8333-333333333333',
                'scope' => 'service',
            ],
        ],

        'forged_issuer_service.jwt' => [
            'alg' => 'HS256',
            'key' => 'issuer:geo',
            'verify_now' => 1700000000,
            'outcome' => 'forged',
            'scope' => 'service',
            'claims' => [
                'iss' => 'logger',
                'aud' => 'auth',
                'iat' => 1700000000,
                'nbf' => 1700000000,
                'exp' => 1700000060,
                'jti' => '44444444-4444-4444-8444-444444444444',
                'scope' => 'service',
            ],
        ],
    ],
];
