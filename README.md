<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/jwt-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=jwt-for-laravel">
    <img src="art/hero.png" alt="JWT for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/jwt-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/jwt-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/jwt-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/jwt-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/jwt-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/jwt-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
</p>
<!-- roundly-badges:end -->

# JWT for Laravel

Native **RS256 user tokens** and **HS256 service tokens**, guard drivers, a jti denylist and
claim-based authorization for Laravel — with **zero third-party crypto**. The JOSE core (compact
JWS sign/verify, base64url, RSA and HMAC key handling) comes from our own audited
[`crypto-for-laravel`](https://github.com/roundly-consulting/crypto-for-laravel), which builds on
PHP's own `ext-openssl`/`hash_hmac`; there is no third-party runtime JWT dependency of any kind.
This package owns the JWT *policy* — claims, guards, denylist, service-token issuer binding — and
nothing else.

Two token families, strictly separated by algorithm and purpose:

- **User tokens — RS256 (asymmetric).** Minted by issuer apps holding the private key; verified
  offline everywhere with only the public PEM.
- **Service tokens — HS256 (shared or per-issuer secrets).** Machine-to-machine only.

Security is the point: single-algorithm pinning (so `alg:none` and RS256↔HS256 confusion are
structurally impossible), constant-time HMAC comparison, PEM-as-HMAC rejection, a 256-bit minimum
HMAC secret that must be ≥32 *random* bytes (generate one with `openssl rand -base64 48`; a single
repeated byte is rejected), RSA key-type and key-size (≥ 2048-bit) validation, mandatory `iss`/`aud`
pinning (empty pins are a hard misconfiguration, never a vacuous match), per-call clock leeway with
no global state, rejection of the `crit` header, RFC 8725 explicit typing (a present `typ` must be
`JWT`), an 8 KB cap on any token before decoding, and a fail-closed denylist (a token with no `jti`
can never authenticate while denylisting is on). Misconfiguration always surfaces as a 500 — a
missing key or secret can never masquerade as a silent 401.

## Requirements

- PHP 8.4+
- Laravel 12 or 13
- `ext-openssl`, `ext-json`

## Integrates with

- **[`crypto-for-laravel`](https://github.com/roundly-consulting/crypto-for-laravel)** (hard
  dependency) — supplies the compact-JWS serializer, the strict base64url codec, the RS256/HS256
  signers and verifiers, and the RSA/HMAC key guards. It is zero-config: this package's own service
  provider builds every keyed object from **`config/jwt.php`** (your PEM paths and secrets), so
  nothing about your configuration changes. Crypto failures are translated at the boundary — you
  keep catching `RoundlyConsulting\Jwt\Jose\Exceptions\*` exactly as before.
- **[`enums-for-laravel`](https://github.com/roundly-consulting/enums-for-laravel)** — enum helpers
  on `Scope`.
- **[`package-toolkit-for-laravel`](https://github.com/roundly-consulting/package-toolkit-for-laravel)**
  — the service-provider bootstrapper. The config file, its `jwt-config` publish tag and the
  `jwt:generate-keys` command are declared through it, and it adds a `Jwt` section to
  `php artisan about` (`php artisan about --only=jwt`) reporting the algorithms, whether the signing
  key, verification key, issuer, audience and service secret are **SET** or **MISSING**, the access
  token TTL, and whether the denylist check and claim authorization are on. It never prints key
  material, secrets or key paths.

## Installation

```bash
composer require roundly-consulting/jwt-for-laravel
```

Publish the config file:

```bash
php artisan vendor:publish --tag="jwt-config"
```

On an **issuer** app (one that mints user tokens), generate an RSA keypair:

```bash
php artisan jwt:generate-keys
```

On a **verify-only** app, copy the issuer's public key to the path in `JWT_PUBLIC_KEY_PATH`
(default `storage/jwt-public.pem`) — no private key is needed.

## Configuration

The published `config/jwt.php` is fully env-driven and works with zero host config for
verification once the keys/secret are set. Every key and its backing env var:

| Config key | Env var | Default | Purpose |
|---|---|---|---|
| `private_key_path` | `JWT_PRIVATE_KEY_PATH` | `null` | RSA private key path (issuers only) |
| `public_key_path` | `JWT_PUBLIC_KEY_PATH` | `storage_path('jwt-public.pem')` | RSA public key path |
| `issuer` | `JWT_ISSUER` | `null` | Pinned `iss` — **required**; empty throws `JwtMisconfigured` |
| `audience` | `JWT_AUDIENCE` | `null` | Pinned `aud` — **required**; empty throws `JwtMisconfigured` |
| `ttl` | `JWT_TTL` | `900` | Access-token lifetime (seconds) |
| `challenge_ttl` | `JWT_CHALLENGE_TTL` | `300` | `2fa_pending` lifetime |
| `verify_ttl` | `JWT_VERIFY_TTL` | `3600` | `email_verify` lifetime |
| `leeway` | `JWT_LEEWAY` | `10` | Clock-skew tolerance (seconds) |
| `kid` | `JWT_KID` | `null` | Emitted `kid` header when set |
| `guard.scope` | — | `access` | Scope required to authenticate the `jwt` guard |
| `guard.identity` | — | `TokenUser::class` | Claims-mode identity class |
| `guard.token_version` | — | `null` | `callable|invokable-class|null` returning the user's current version |
| `guard.check_denylist` | `JWT_CHECK_DENYLIST` | `true` | Enforce the jti denylist |
| `denylist.store` | `JWT_DENYLIST_STORE` | `redis` | Cache store backing the denylist |
| `denylist.prefix` | `JWT_DENYLIST_PREFIX` | `jwt:denylist:` | Denylist cache-key prefix |
| `service.secret` | `SERVICE_JWT_SECRET` | `null` | HS256 shared secret, ≥32 random bytes (`openssl rand -base64 48`) |
| `service.secrets` | `SERVICE_JWT_SECRETS` | `null` | Per-issuer secrets `"billing:<secret>,api:<secret>"`; overrides `secret` |
| `service.name` | `JWT_SERVICE_NAME` | `app.service`, else `Str::slug(app.name)` | This service's own name: the `aud` inbound service tokens must carry. Set it explicitly to a stable id — the app name can change |
| `service.issuer` | `JWT_SERVICE_ISSUER` | `env('APP_SERVICE')`, else `service.name` | The `iss` of service tokens this app mints |
| `service.audience` | `JWT_SERVICE_AUDIENCE` | `null` | Default service-token `aud` |
| `service.ttl` | `SERVICE_JWT_TTL` | `60` | Service-token lifetime (seconds) |
| `service.issuers` | `JWT_SERVICE_ISSUERS` | `[]` (any) | Comma-separated issuer allow-list |
| `authorize_from_claims` | `JWT_AUTHORIZE_FROM_CLAIMS` | `false` | Enable the claim-based `Gate::before` |

## Usage

### Quick start with the `Jwt` facade

The `Jwt` facade is the one obvious entry point — every call routes to the same container-bound
contract, so host overrides and tests keep working. It is auto-registered as the global alias
`Jwt` (or import `RoundlyConsulting\Jwt\Facades\Jwt`).

```php
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;

// Mint an access token with a fluent, self-documenting request.
$issued = Jwt::mintAccessToken(
    AccessTokenRequest::for($user->id)
        ->email($user->email, verified: $user->hasVerifiedEmail())
        ->tokenVersion($user->token_version)
        ->permissions('posts.view', 'posts.edit')
);

$claims = Jwt::verify($issued->token);   // RS256 + iss/aud pinned
Jwt::logout($issued);                     // denylist it (one-call logout)
$current = Jwt::claims();                 // current request's claims, or null
```

Facade surface: `mintAccessToken()`, `mint()`, `mintChallengeToken()`, `mintEmailVerifyToken()`,
`verify()`, `service()`, `caller()`, `denylist()`, `logout()`, `denyClaims()`, `claims()`,
`audienceFor()`, `guardSettings()`.

### Mint a user access token

Prefer the facade above. Under the hood it delegates to the `UserTokenIssuer` contract (bound to
`NativeUserTokenIssuer`), which you can also resolve directly for DI/testing:

```php
use RoundlyConsulting\Jwt\UserTokens\AccessTokenRequest;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

$issued = app(UserTokenIssuer::class)->mintAccessToken(
    AccessTokenRequest::for($user->id)->email($user->email, verified: true)
);

$issued->token;      // the compact JWS string
$issued->expiresAt;  // CarbonImmutable
$issued->jti;        // the token id (store it to denylist later)
```

The request also carries the minting parameters and the OIDC session claims. `audience()` and
`ttl()` steer the issuer (they are never written into the payload); `sid`, `amr` and `auth_time`
are emitted only when you set them, so existing call sites mint exactly what they always did:

```php
AccessTokenRequest::for($user->id)
    ->audience(Jwt::audienceFor('clients'))   // aud — defaults to jwt.audience
    ->ttl(600)                                // seconds — defaults to jwt.ttl
    ->sessionId($familyId)                    // sid
    ->authMethods('pwd', 'otp', 'mfa')        // amr (RFC 8176)
    ->authTime($loggedInAt);                  // auth_time — int or any DateTimeInterface

$claims->sessionId();    // ?string
$claims->authMethods();  // list<string>, [] when absent
$claims->authTime();     // ?int
```

### Challenge, email-verify and custom scopes

The `2fa_pending` and `email_verify` convenience mints consume the configured `challenge_ttl`
and `verify_ttl` — no more hand-passing the number:

```php
Jwt::mintChallengeToken($subject);                 // scope=2fa_pending, exp = challenge_ttl
Jwt::mintEmailVerifyToken($subject, $user->email); // scope=email_verify, exp = verify_ttl

// Any other scope via the generic mint():
Jwt::mint($subject, 'my_custom_scope', ttl: 120, extraClaims: ['org' => 42]);
```

The four built-in scopes are a backed enum. `mint()` accepts a `Scope` case or any string, so
custom scopes stay free strings:

```php
use RoundlyConsulting\Jwt\UserTokens\Scope;

Scope::Access->value;        // 'access'
Scope::TwoFaPending->value;  // '2fa_pending'
Scope::EmailVerify->value;   // 'email_verify'
Scope::Service->value;       // 'service'

Jwt::mint($subject, Scope::Access, ttl: 900);  // pass an enum case, or any string
```

### Verify a token offline

```php
$claims = Jwt::verify($jwt);   // or app(UserTokenVerifier::class)->verify($jwt)
$claims->string('sub');
$claims->list('permissions');

Jwt::verify($jwt, Jwt::audienceFor('clients'));   // pin another audience for this call
```

Invalid tokens throw a `RoundlyConsulting\Jwt\Jose\Exceptions\JwtException` subclass
(`InvalidSignature`, `TokenExpired`, `AlgorithmMismatch`, `ClaimMismatch`, `UnexpectedTokenType`,
`MalformedToken`, …). Minting a claim set that can't be JSON-encoded (e.g. non-UTF-8 bytes) throws
`UnencodableClaims`, also a `JwtException` — so a single catch covers both minting and verifying.

### Wire the guards

Declare the guards in `config/auth.php` — the package provides the drivers:

```php
'guards' => [
    // Claims mode: build a TokenUser straight from the token (no DB).
    'api' => ['driver' => 'jwt'],

    // Provider mode: resolve a real Eloquent user via `sub`.
    // 'api' => ['driver' => 'jwt', 'provider' => 'users'],

    'service' => ['driver' => 'service-jwt'],
],
```

Then protect routes as usual:

```php
Route::middleware('auth:api')->get('/me', fn () => request()->user());
Route::middleware('auth:service')->post('/internal/sync', SyncController::class);
```

In provider mode, set `guard.token_version` so a bumped version invalidates old tokens. Prefer an
invokable class — it survives `php artisan config:cache`, a closure does not. A value the guard
cannot call (missing class, no `__invoke`) throws `JwtMisconfigured` rather than silently skipping
the check:

```php
'guard' => [
    'token_version' => \App\Auth\TokenVersion::class,   // __invoke(Authenticatable $user): int
],
```

### Multiple guards

Several account types (say `users` and `clients`, each with its own table) can each run on their
own `jwt` guard. Every `jwt` guard resolves `sub` through **its own** provider, so give each guard
its **own audience** — otherwise a users token with `sub = 5` authenticates as client #5:

```php
// config/auth.php
'guards' => [
    'users'   => ['driver' => 'jwt', 'provider' => 'users',   'audience' => env('JWT_USERS_AUDIENCE', 'app-users')],
    'clients' => ['driver' => 'jwt', 'provider' => 'clients', 'audience' => env('JWT_CLIENTS_AUDIENCE', 'app-clients')],
],
```

Each guard reads these optional keys from its own `auth.guards.<name>` array, falling back to the
global value:

| `auth.guards.<name>` key | Falls back to | Type |
|---|---|---|
| `audience` | `jwt.audience` | non-empty string |
| `scope` | `jwt.guard.scope` | string or `Scope` case |
| `token_version` | `jwt.guard.token_version` | invokable class-string (or closure — not config-cacheable) |
| `check_denylist` | `jwt.guard.check_denylist` | bool |
| `identity` | `jwt.guard.identity` | class-string of a `ClaimsAuthenticatable` |

Mint for, verify against and read a specific guard:

```php
Jwt::mintAccessToken(AccessTokenRequest::for($client->id)->audience(Jwt::audienceFor('clients')));

Jwt::audienceFor('clients');     // 'app-clients' — auth.guards.clients.audience, else jwt.audience
Jwt::guardSettings('clients');   // JwtGuardSettings: guard, audience, scope, checkDenylist, identity, tokenVersion
Jwt::claims('clients');          // that guard's verified claims, or null
```

`audienceFor()` / `guardSettings()` throw `JwtMisconfigured` for a guard that is not a `jwt` guard.
`jwt.audience` stays required: it is the default every guard without its own `audience` uses.

### Issue and send a service token

```php
use RoundlyConsulting\Jwt\Facades\Jwt;

$token = Jwt::service()->issue('target-service')->token;

// Or attach one to an outbound internal HTTP call:
Jwt::caller()->request('target-service')
    ->post('https://target.internal/endpoint', [...]);
```

A missing, too-short or PEM-shaped `SERVICE_JWT_SECRET` raises `ServiceAuthMisconfigured` (a
500), never a silent 401.

`'target-service'` is the receiver's **service name** — inbound tokens must carry it as `aud`. Each
service sets its own with `JWT_SERVICE_NAME`; unset, it falls back to `config('app.service')`, then
to a slug of `APP_NAME`. Set it explicitly to a stable identifier: renaming the app would otherwise
re-pin the service and break every caller.

**Choosing a secret mode.** With one shared `SERVICE_JWT_SECRET`, possession of the secret is
the only proof — any holder can mint a token claiming any `iss`, so the issuer allow-list is a
label, not authentication. For real service identity set `SERVICE_JWT_SECRETS` instead
(`"billing:<secret>,api:<secret>"`): each service signs with its own secret, the verifier picks
the secret by the token's `iss` (a `kid`-style lookup), and a forged `iss` selects a secret its
signature cannot match. One leaked secret then no longer impersonates the whole mesh.

### Log a user out (denylist a jti)

```php
use RoundlyConsulting\Jwt\Facades\Jwt;

Jwt::logout($issued);                 // from a freshly issued token
Jwt::denyClaims(Jwt::verify($jwt));   // or from verified claims (reads jti + exp)

// Power users not using the facade:
app(\RoundlyConsulting\Jwt\Denylist\Contracts\Denylist::class)->denyToken($issued);
```

The entry auto-evicts once the token can no longer verify (`exp` + `jwt.leeway`). The `jwt` guard rejects denylisted
tokens while `guard.check_denylist` is true.

### Events

The package dispatches lifecycle events (via the container's event dispatcher; a no-op when none
is bound) so hosts can audit, meter or alert without forking. Payloads are minimal and carry **no
token strings, secrets or keys**:

| Event | When | Payload |
|---|---|---|
| `UserTokenIssued` | a user token is minted | `subject`, `scope`, `jti`, `expiresAt` |
| `ServiceTokenIssued` | a service token is issued | `issuer`, `audience`, `jti`, `expiresAt` |
| `TokenVerificationFailed` | an explicit `Jwt::verify()` fails | `reason`, `exceptionClass` |
| `TokenDenied` | a jti is denylisted | `jti`, `until` |

`TokenVerificationFailed` fires only from the explicit verify path — never from the guard's silent
per-request resolution, so anonymous probes don't spam it.

```php
use RoundlyConsulting\Jwt\Events\UserTokenIssued;

Event::listen(function (UserTokenIssued $event): void {
    Log::info('token issued', ['sub' => $event->subject, 'scope' => $event->scope]);
});
```

### Claim-based authorization

Set `authorize_from_claims` to `true` and abilities listed in the token's `permissions` claim are
granted through Laravel's Gate:

```php
if ($request->user()->can('posts.edit')) {
    // ...
}
```

The hook returns `null` (not `false`) on a miss, so your own gates and policies still run.

### `jwt:generate-keys`

```bash
php artisan jwt:generate-keys          # writes both PEMs; refuses to overwrite
php artisan jwt:generate-keys --force  # overwrite existing keys
```

Generates a 2048-bit RSA keypair; the private key is written with `0600` permissions.

## Standards-based parity

The package is verification-compatible with standard JWS/JWT tokens, proven by committed static
parity fixtures and the RFC 7515 example vectors under `tests/fixtures/` — **with zero third-party
JWT or crypto libraries in `composer.json`** (architecture tests keep `src/` free of any third-party
JWT dependency by allow-listing only permitted vendor roots, and assert no crypto primitive is
re-implemented here: signing, verification, HMAC and constant-time comparison may only come from
`crypto-for-laravel`). The fixtures are a test aid, not a runtime dependency.

## Testing

```bash
composer test
```

## Changelog & Contributing

Please see [CHANGELOG.md](CHANGELOG.md) for what has changed. Issues and pull requests are welcome.

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=jwt-for-laravel).
If it saves you time, please consider supporting our open-source work — every donation helps fund
maintenance, new features and new packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md). Maintained by roundly-consulting.
