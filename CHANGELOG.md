# Changelog

All notable changes to `jwt-for-laravel` will be documented in this file.

## 1.0.0 - Unreleased

- Initial release: RS256 user tokens and HS256 service tokens on the `crypto-for-laravel` JOSE
  core — single-algorithm pinning, mandatory `iss`/`aud` pinning, RFC 8725 `typ` checks, an 8 KB
  token cap, `crit` rejection, and a 32-byte random minimum for HMAC secrets.
- `jwt` guard driver with a fail-closed `jti` denylist, `token_version` revocation and
  claim-based authorization; misconfiguration always surfaces as a 500, never a silent 401.
- Service tokens with per-issuer secrets, caller-defined claims and reserved identity claims.
- `Scope` enum accepted wherever scopes are minted or configured (`Scope|string`).
- Multiple guards with per-guard audiences and `sid` / `amr` / `auth_time` session claims.
- `jwt:generate-keys` command and an `artisan about` section.

### Fixed

- Denylist entries are held through the verify leeway, so a logged-out token can't come back
  for `leeway` seconds after `exp`.
- An uncallable `token_version` (global or per guard) now throws instead of silently switching
  version checks off.
