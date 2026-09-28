# Changelog

All notable changes to `jwt-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

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
  so several account types can run side by side.
- Service tokens with a shared secret or per-issuer secrets (`SERVICE_JWT_SECRETS`) through
  `Jwt::services()`: `issue()`, `verify()`, `request()` / `authenticate()` for outbound calls, and
  `claims()` of the calling service on a `service-jwt` guard.
- `Jwt::jwks()` (RFC 7517 JWK Set, with `alg`, `use` and the configured `kid`) and
  `Jwt::publicKey()` to publish the verification key.
- `Jwt::fake()` — a recording fake over in-memory RSA keys with `actingAs($claims, $guard)`,
  `assertMinted()`, `assertServiceTokenIssued()`, `assertDenied()` and an `assertNothing…()` for
  each.
- A jti denylist for one-call logout (`Jwt::logout()`, `Jwt::denyClaims()`).
- Built-in `Scope` enum (`access`, `2fa_pending`, `email_verify`, `service`) plus free-form custom
  scopes and extra claims.
- Optional claim-based authorization: abilities in the token's `permissions` claim are granted
  through Laravel's Gate.
- `UserTokenIssued`, `ServiceTokenIssued`, `TokenVerificationFailed` and `TokenDenied` events that
  never carry token strings or secrets.
- Strict verification: single-algorithm pinning, mandatory `iss`/`aud`, RSA key-size and HMAC
  secret-strength checks, and a size cap on incoming tokens.
- `php artisan jwt:generate-keys` to create an RSA key pair with safe file permissions.

### Changed (since the pre-release API)

- `Jwt::service()` and `Jwt::caller()` merged into `Jwt::services()`; the `ServiceCaller` class is
  removed (`request()` / `authenticate()` live on `Services`).
- `Jwt::audienceFor($g)` → `Jwt::guard($g)->audience()`; `Jwt::guardSettings($g)` →
  `Jwt::guard($g)->settings()`; `Jwt::claims($g)` → `Jwt::guard($g)->claims()` (the guard-less
  "first jwt guard with a user" form is gone — name the guard). `Jwt::guard()` throws
  `JwtMisconfigured` for a guard that is not a `jwt` guard.
- `JwtManager` is no longer `final` (the fake extends it).

