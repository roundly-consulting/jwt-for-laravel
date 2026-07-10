<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\UserTokens\TokenUser;

return [
    // ── User tokens (RS256) ──────────────────────────────────────────────
    'private_key_path' => env('JWT_PRIVATE_KEY_PATH'),   // nullable: verify-only apps omit it
    'public_key_path' => env('JWT_PUBLIC_KEY_PATH', storage_path('jwt-public.pem')),
    'issuer' => env('JWT_ISSUER'),                    // required: minting/verifying throws when empty
    'audience' => env('JWT_AUDIENCE'),                // required: minting/verifying throws when empty
    'ttl' => (int) env('JWT_TTL', 900),               // access token seconds
    'challenge_ttl' => (int) env('JWT_CHALLENGE_TTL', 300), // 2fa_pending
    'verify_ttl' => (int) env('JWT_VERIFY_TTL', 3600),      // email_verify
    'leeway' => (int) env('JWT_LEEWAY', 10),          // clock-skew seconds
    'kid' => env('JWT_KID'),                          // emit-only metadata when set

    // ── User guard ──────────────────────────────────────────────────────
    'guard' => [
        'scope' => 'access',                              // required scope to authenticate
        'identity' => TokenUser::class,                   // claims-mode identity class
        'token_version' => null,                          // callable|invokable-class|null: fn(Authenticatable): int
        'check_denylist' => (bool) env('JWT_CHECK_DENYLIST', true),
    ],

    // ── jti denylist ────────────────────────────────────────────────────
    'denylist' => [
        'store' => env('JWT_DENYLIST_STORE', 'redis'),
        'prefix' => env('JWT_DENYLIST_PREFIX', 'jwt:denylist:'),
    ],

    // ── Service tokens (HS256) ──────────────────────────────────────────
    'service' => [
        // Shared-secret mode: one ≥32-byte secret for the whole mesh
        // (`openssl rand -base64 48`). Any holder can then claim any `iss`.
        'secret' => env('SERVICE_JWT_SECRET'),
        // Per-issuer mode (recommended): "billing:<secret>,api:<secret>".
        // Binds each `iss` to its own secret; overrides `secret` when set.
        'secrets' => env('SERVICE_JWT_SECRETS'),
        'issuer' => env('JWT_SERVICE_ISSUER', env('APP_SERVICE')),
        'audience' => env('JWT_SERVICE_AUDIENCE'),
        'ttl' => (int) env('SERVICE_JWT_TTL', 60),
        'issuers' => array_values(array_filter(array_map('trim', explode(',', (string) env('JWT_SERVICE_ISSUERS', ''))))), // allow-list; empty ⇒ any
    ],

    // ── Claim-based authorization ───────────────────────────────────────
    'authorize_from_claims' => (bool) env('JWT_AUTHORIZE_FROM_CLAIMS', false),
];
