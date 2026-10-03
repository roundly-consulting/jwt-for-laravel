<?php

declare(strict_types=1);

use RoundlyConsulting\Jwt\UserTokens\TokenUser;

return [
    // Every value is read strictly: an absent key takes its default, but a present
    // value of the wrong shape (a TTL of 'five', a non-list `issuers`, a malformed
    // `secrets` pair, an `identity` that is not a ClaimsAuthenticatable) throws
    // JwtMisconfigured naming the key instead of silently falling back.

    // ── User tokens (RS256) ──────────────────────────────────────────────
    // `jwt:generate-keys` writes both. Only minting reads the private key, so a
    // verify-only app just never creates it. `.key` because a stock Laravel
    // `.gitignore` already excludes `/storage/*.key`.
    'private_key_path' => env('JWT_PRIVATE_KEY_PATH', storage_path('jwt-private.key')),
    'public_key_path' => env('JWT_PUBLIC_KEY_PATH', storage_path('jwt-public.pem')),
    'issuer' => env('JWT_ISSUER'),                    // required: minting/verifying throws when empty
    'audience' => env('JWT_AUDIENCE'),                // required: minting/verifying throws when empty
    'ttl' => env('JWT_TTL', 900),                     // access token seconds (≥1)
    'challenge_ttl' => env('JWT_CHALLENGE_TTL', 300), // 2fa_pending (≥1)
    'verify_ttl' => env('JWT_VERIFY_TTL', 3600),      // email_verify (≥1)
    'leeway' => env('JWT_LEEWAY', 10),                // clock-skew seconds (≥0)
    'kid' => env('JWT_KID'),                          // emit-only metadata when set

    // ── User guard ──────────────────────────────────────────────────────
    // Defaults for every `jwt` guard. With several jwt guards (e.g. `users`
    // and `clients`), each `auth.guards.<name>` array may override `audience`,
    // `scope`, `token_version`, `check_denylist` and `identity`; give each
    // guard its own `audience`, or one guard's tokens authenticate on another.
    'guard' => [
        'scope' => 'access',                              // required scope to authenticate
        'identity' => TokenUser::class,                   // claims-mode identity class
        'token_version' => null,                          // invokable-class|callable|null: fn(Authenticatable): int (closures break config:cache)
        'check_denylist' => env('JWT_CHECK_DENYLIST', true),
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
        // This service's own name: the `aud` every inbound service token must carry
        // (and the default `iss` below). Set it explicitly to a STABLE identifier —
        // unset, it falls back to a host's `app.service`, then to a slug of
        // `app.name`, which can change and silently re-pin every caller.
        'name' => env('JWT_SERVICE_NAME'),
        'issuer' => env('JWT_SERVICE_ISSUER', env('APP_SERVICE')), // unset ⇒ the service name
        'audience' => env('JWT_SERVICE_AUDIENCE'),
        'ttl' => env('SERVICE_JWT_TTL', 60),               // seconds (≥1)
        'issuers' => array_values(array_filter(array_map('trim', explode(',', (string) env('JWT_SERVICE_ISSUERS', ''))))), // allow-list; empty ⇒ any
    ],

    // ── Claim-based authorization ───────────────────────────────────────
    'authorize_from_claims' => env('JWT_AUTHORIZE_FROM_CLAIMS', false),
];
