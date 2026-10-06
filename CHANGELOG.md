# Changelog

All notable changes to `jwt-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Security

- Per-issuer service tokens (`SERVICE_JWT_SECRETS`): a token whose `iss` is not in the secret map
  is now always rejected as `InvalidSignature`, also when the issuer is on the
  `JWT_SERVICE_ISSUERS` allow-list. Before, such a token was verified against a fixed secret that
  is readable in the public source, so anyone could mint a service token that every `service-jwt`
  guard accepted. The timing burn for an unknown issuer now uses a random per-instance key.

### Fixed

- `Claims::int()` rejects a whole float outside the 64-bit integer range (`INF`, `1e19`, `2^64`)
  with `ClaimMismatch` instead of wrapping it to an unrelated integer, so a `tv`, `auth_time` or
  denylist `exp` claim can no longer read as a different number. It now uses crypto's integer rules.

## 1.0.0 - 2026-10-03

Initial public release.

### Added

- RS256 user tokens minted by apps holding the private key and verified offline anywhere with the
  public key; HS256 service tokens for machine-to-machine calls.
- A `Jwt` facade over the injectable `JwtManager`: `mintAccessToken()`, `mint()`,
  `mintChallengeToken()`, `mintEmailVerifyToken()`, `verify()`, `logout()`, `denyClaims()`,
  `denylist()`, plus the `guard($name)` and `services()` sub-accessors.
- `Jwt::guard($name)` — one `jwt` guard: `mint()` / `mintAccessToken()` / `verify()` for its own
  audience, `claims()` of the current request on it, `settings()` and `audience()`.
- `jwt` and `service-jwt` guard drivers, with per-guard audience, scope and token-version checks
  so several account types can run side by side. Both honour `setUser()`, so Laravel's
  `actingAs($user, $guard)` works on them.
- Service tokens with a shared secret or per-issuer secrets (`SERVICE_JWT_SECRETS`) through
  `Jwt::services()`: `issue()`, `verify()`, `request()` / `authenticate()` for outbound calls, and
  `claims()` of the calling service on a `service-jwt` guard.
- `Jwt::jwks()` (RFC 7517 JWK Set, with `alg`, `use` and the configured `kid`) and
  `Jwt::publicKey()` to publish the verification key.
- `Jwt::fake()` — a recording fake over in-memory RSA keys and an in-memory denylist (no Redis
  needed) with `actingAs($claims, $guard)`,
  `assertMinted()`, `assertServiceTokenIssued()`, `assertDenied()` and an `assertNothing…()` for
  each.
- A jti denylist for one-call logout (`Jwt::logout()`, `Jwt::denyClaims()`).
- Built-in `Scope` enum (`access`, `2fa_pending`, `email_verify`, `service`) plus free-form custom
  scopes and extra claims.
- Optional claim-based authorization: abilities in the token's `permissions` claim are granted
  through Laravel's Gate, for a claims-mode `TokenUser` and for the Eloquent user a token
  authenticated in provider mode.
- `UserTokenIssued`, `ServiceTokenIssued`, `TokenVerificationFailed` and `TokenDenied` events that
  never carry token strings or secrets.
- Strict verification: single-algorithm pinning, mandatory `iss`/`aud`, RSA key-size and HMAC
  secret-strength checks, and a size cap on incoming tokens.
- `php artisan jwt:generate-keys` to create an RSA key pair with safe file permissions — by default
  at `storage/jwt-private.key` and `storage/jwt-public.pem`, where the config reads them.

### Changed (since the pre-release API)

- `Jwt::service()` and `Jwt::caller()` merged into `Jwt::services()`; the `ServiceCaller` class is
  removed (`request()` / `authenticate()` live on `Services`).
- `Jwt::audienceFor($g)` → `Jwt::guard($g)->audience()`; `Jwt::guardSettings($g)` →
  `Jwt::guard($g)->settings()`; `Jwt::claims($g)` → `Jwt::guard($g)->claims()` (the guard-less
  "first jwt guard with a user" form is gone — name the guard). `Jwt::guard()` throws
  `JwtMisconfigured` for a guard that is not a `jwt` guard.
- `JwtManager` is no longer `final` (the fake extends it).

- The `check_denylist` and `authorize_from_claims` switches are read strictly: `.env` spellings
  `off`/`0`/`no` mean off (the old `(bool) env()` cast read them as on), and a typo such as
  `disabled` throws `JwtMisconfigured` naming the key — a per-guard `check_denylist` typo no
  longer defers to the global value.
