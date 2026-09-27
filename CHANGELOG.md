# Changelog

All notable changes to `jwt-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- RS256 user tokens minted by apps holding the private key and verified offline anywhere with the
  public key; HS256 service tokens for machine-to-machine calls.
- A `Jwt` facade: `mintAccessToken()`, `mint()`, `mintChallengeToken()`, `mintEmailVerifyToken()`,
  `verify()`, `logout()`, `claims()` and more.
- `jwt` and `service-jwt` guard drivers, with per-guard audience, scope and token-version checks
  so several account types can run side by side.
- Service tokens with a shared secret or per-issuer secrets (`SERVICE_JWT_SECRETS`), issued and
  sent with `Jwt::caller()`.
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
