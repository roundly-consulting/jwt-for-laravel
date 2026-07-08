<p align="center">
  <a href="https://roundly-consulting.com/open-source">
    <img src="art/hero.png" alt="JWT for Laravel — Roundly open source" width="100%">
  </a>
</p>

# JWT for Laravel

Native **RS256 user tokens** and **HS256 service tokens**, guard drivers, a jti denylist and
claim-based authorization for Laravel — with **zero third-party crypto**. The entire JOSE core
(compact JWS encode/verify, base64url, key handling) is implemented on top of PHP's own
`ext-openssl`/`hash_hmac`; there is no third-party runtime JWT dependency of any kind.

Two token families, strictly separated by algorithm and purpose:

- **User tokens — RS256 (asymmetric).** Minted by issuer apps holding the private key; verified
  offline everywhere with only the public PEM.
- **Service tokens — HS256 (shared secret).** Machine-to-machine only.

Security is the point: single-algorithm pinning (so `alg:none` and RS256↔HS256 confusion are
structurally impossible), constant-time HMAC comparison, PEM-as-HMAC rejection, RSA key-type and
key-size (≥ 2048-bit) validation, per-call clock leeway with no global state, and rejection of the
`crit` header.

## Requirements

- PHP 8.4+
- Laravel 12 or 13
- `ext-openssl`, `ext-json`

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
| `algo` | `JWT_ALGO` | `RS256` | User-token algorithm |
| `issuer` | `JWT_ISSUER` | `null` | Pinned `iss` |
| `audience` | `JWT_AUDIENCE` | `null` | Pinned `aud` |
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
| `service.secret` | `SERVICE_JWT_SECRET` | `null` | HS256 shared secret |
| `service.issuer` | `JWT_SERVICE_ISSUER` | `env('APP_SERVICE')` | This service's name (token `iss`) |
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
`verify()`, `service()`, `caller()`, `denylist()`, `logout()`, `denyClaims()`, `claims()`.

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

### Challenge, email-verify and custom scopes

The `2fa_pending` and `email_verify` convenience mints consume the configured `challenge_ttl`
and `verify_ttl` — no more hand-passing the number:

```php
Jwt::mintChallengeToken($subject);                 // scope=2fa_pending, exp = challenge_ttl
Jwt::mintEmailVerifyToken($subject, $user->email); // scope=email_verify, exp = verify_ttl

// Any other scope via the generic mint():
Jwt::mint($subject, 'my_custom_scope', ttl: 120, extraClaims: ['org' => 42]);
```

The four built-in scopes have discoverable constants (still plain strings — custom scopes remain
free strings):

```php
use RoundlyConsulting\Jwt\UserTokens\Scopes;

Scopes::ACCESS;          // 'access'
Scopes::TWO_FA_PENDING;  // '2fa_pending'
Scopes::EMAIL_VERIFY;    // 'email_verify'
Scopes::SERVICE;         // 'service'
```

### Verify a token offline

```php
$claims = Jwt::verify($jwt);   // or app(UserTokenVerifier::class)->verify($jwt)
$claims->string('sub');
$claims->list('permissions');
```

Invalid tokens throw a `RoundlyConsulting\Jwt\Jose\Exceptions\JwtException` subclass
(`InvalidSignature`, `TokenExpired`, `AlgorithmMismatch`, `ClaimMismatch`, …).

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

In provider mode, set `guard.token_version` so a bumped version invalidates old tokens:

```php
'guard' => [
    'token_version' => fn (\App\Models\User $user): int => $user->token_version,
],
```

### Issue and send a service token

```php
use RoundlyConsulting\Jwt\Facades\Jwt;

$token = Jwt::service()->issue('target-service')->token;

// Or attach one to an outbound internal HTTP call:
Jwt::caller()->request('target-service')
    ->post('https://target.internal/endpoint', [...]);
```

A missing `SERVICE_JWT_SECRET` raises `ServiceAuthMisconfigured` (a 500), never a silent 401.

### Log a user out (denylist a jti)

```php
use RoundlyConsulting\Jwt\Facades\Jwt;

Jwt::logout($issued);                 // from a freshly issued token
Jwt::denyClaims(Jwt::verify($jwt));   // or from verified claims (reads jti + exp)

// Power users not using the facade:
app(\RoundlyConsulting\Jwt\Denylist\Contracts\Denylist::class)->denyToken($issued);
```

The entry auto-evicts when the token would have expired. The `jwt` guard rejects denylisted
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
JWT or crypto libraries in `composer.json`** (an architecture test keeps `src/` and `tests/` free of
any third-party JWT dependency by allow-listing only permitted vendor roots). The fixtures are a
test aid, not a runtime dependency.

## Testing

```bash
composer test
```

## Changelog & Contributing

Please see the commit history for changes. Issues and pull requests are welcome.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md). Maintained by roundly-consulting.
