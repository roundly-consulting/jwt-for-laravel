<?php

declare(strict_types=1);

// Guard against any third-party JWT/crypto dependency by allow-listing only the
// permitted vendor roots (roundly + Laravel/Symfony runtime). Our own
// crypto-for-laravel is allowed — it owns the JOSE/signature/codec primitives —
// but any accidental `use` of a non-allowed vendor fails the suite.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt')
    ->toOnlyUse([
        'RoundlyConsulting\Jwt',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'Illuminate',
        'Carbon',
        'config',
        'config_path',
    ]);

arch('test support only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Jwt\Tests')
    ->toOnlyUse(['RoundlyConsulting\Jwt', 'RoundlyConsulting\Crypto', 'Illuminate', 'Orchestra\Testbench']);

// Every cryptographic primitive comes from crypto-for-laravel — never a
// third-party JOSE/JWT library, and never a hand-rolled copy back inside this
// package. Signing, verification, HMAC and constant-time comparison must not be
// re-implemented here.
arch('no crypto primitive is re-implemented locally')
    ->expect('RoundlyConsulting\Jwt')
    ->not->toUse([
        'hash_hmac',
        'hash_equals',
        'openssl_sign',
        'openssl_verify',
        'openssl_pkey_new',
        'openssl_pkey_get_private',
        'openssl_pkey_get_public',
        'openssl_pkey_get_details',
        'base64_encode',
        'base64_decode',
    ]);

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\Jwt')
    ->toUseStrictTypes();

arch('exceptions live in an Exceptions namespace')
    ->expect('RoundlyConsulting\Jwt\Jose\Exceptions')
    ->toBeClasses();
