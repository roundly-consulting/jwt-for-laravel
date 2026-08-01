<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Jwt\Events\ServiceTokenIssued;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenVerifier;
use RoundlyConsulting\Jwt\ServiceTokens\Exceptions\ServiceAuthMisconfigured;
use RoundlyConsulting\Jwt\Support\HmacSecretFactory;
use RoundlyConsulting\Jwt\UserTokens\IssuedToken;
use RoundlyConsulting\Jwt\UserTokens\Scope;

/**
 * Mints and verifies HS256 machine-to-machine service tokens.
 *
 * Every token is pinned to `scope=service` and HS256. Verification requires the
 * audience to equal this service's own name, a non-empty issuer, and — when an
 * allow-list is configured — an issuer within it. A missing shared secret is a
 * misconfiguration ({@see ServiceAuthMisconfigured}, → 500), never a rejected
 * caller (401).
 *
 * Two secret modes:
 * - **Shared** (`secret`): one secret for the whole mesh. Possession of the
 *   secret is the only proof — any holder can mint a token claiming any `iss`,
 *   so the issuer allow-list is a label, not authentication.
 * - **Per-issuer** (`secrets`, issuer → secret map): each service signs with
 *   its own secret, selected on verify by the token's `iss` — like a `kid`
 *   lookup — so `iss` is cryptographically bound to its key and one leaked
 *   secret no longer impersonates every service. The map wins when non-empty.
 */
final class NativeServiceTokenService implements ServiceTokenIssuer, ServiceTokenVerifier
{
    private const SCOPE = Scope::Service->value;

    /**
     * A fixed, high-entropy secret used only to burn an HMAC verification for an
     * unknown issuer, so a known and an unknown `iss` do identical work and fail
     * identically ({@see InvalidSignature}) — the issuer set can't be enumerated
     * by timing or error reason. It never signs or verifies a real token.
     */
    private const DUMMY_SECRET = 'jwt-for-laravel/unknown-issuer/constant-time-burn/8f3c1a9e2b';

    /**
     * The claims a caller may never supply: every one of them is a statement this
     * class makes about the token, not a fact the caller is entitled to assert.
     *
     * @var list<string>
     */
    private const REGISTERED = ['iss', 'aud', 'iat', 'nbf', 'exp', 'jti', 'scope'];

    /**
     * @param  array<string, string>  $secrets  per-issuer secrets; empty ⇒ shared `secret` mode
     * @param  list<string>  $allowedIssuers  empty ⇒ any issuer accepted
     */
    public function __construct(
        private readonly Encoder $encoder,
        private readonly Decoder $decoder,
        #[\SensitiveParameter] private readonly ?string $secret,
        private readonly string $issuer,
        private readonly ?string $defaultAudience,
        private readonly int $ttl,
        private readonly array $allowedIssuers,
        private readonly string $serviceName,
        private readonly int $leeway,
        private readonly ?Dispatcher $events = null,
        #[\SensitiveParameter] private readonly array $secrets = [],
    ) {}

    /**
     * @param  array<string, mixed>  $extraClaims
     */
    public function issue(?string $audience = null, array $extraClaims = []): IssuedToken
    {
        if ($this->issuer === '') {
            throw ServiceAuthMisconfigured::missingIssuer();
        }

        $audience ??= $this->defaultAudience;

        // An audience-less token can never verify anywhere (the receiver pins
        // `aud` to its own name), so refuse to mint one.
        if ($audience === null || $audience === '') {
            throw ServiceAuthMisconfigured::missingAudience();
        }

        $secret = $this->issuingSecret();

        $now = CarbonImmutable::now();
        $expiresAt = $now->addSeconds($this->ttl);
        $jti = (string) Str::uuid();

        // Registered claims are written LAST, so an extra claim can never move the
        // audience, the expiry or the scope. Rejecting outright rather than letting
        // the merge order quietly win: a caller passing `aud` believes it did
        // something, and silently ignoring it is how that belief survives to
        // production.
        $reserved = array_intersect(array_keys($extraClaims), self::REGISTERED);
        if ($reserved !== []) {
            throw ServiceAuthMisconfigured::reservedClaims(array_values($reserved));
        }

        $claims = [
            ...$extraClaims,
            'iss' => $this->issuer,
            'aud' => $audience,
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $expiresAt->getTimestamp(),
            'jti' => $jti,
            'scope' => self::SCOPE,
        ];

        $token = $this->encoder->encode($claims, $secret, Algorithm::HS256);

        $this->events?->dispatch(new ServiceTokenIssued($this->issuer, $audience, $jti, $expiresAt));

        return new IssuedToken($token, $expiresAt, $jti);
    }

    public function verify(string $jwt): Claims
    {
        if ($this->serviceName === '') {
            throw ServiceAuthMisconfigured::missingServiceName();
        }

        // Reject oversized bearer strings before any base64/JSON work — a cheap
        // bound on decode effort that never relies on the web server's header
        // limits.
        if (strlen($jwt) > Decoder::MAX_ENCODED_BYTES) {
            throw new MalformedToken('The token exceeds the maximum permitted length.');
        }

        $claims = $this->decoder->decode($jwt, $this->verificationSecret($jwt), Algorithm::HS256, $this->leeway);

        if ($claims->get('scope') !== self::SCOPE) {
            throw new ClaimMismatch('Service token scope is not "service".');
        }

        if ($claims->get('aud') !== $this->serviceName) {
            throw new ClaimMismatch('Service token audience does not match this service.');
        }

        $issuer = $claims->get('iss');

        if (! is_string($issuer) || $issuer === '') {
            throw new ClaimMismatch('Service token issuer is missing.');
        }

        if ($this->allowedIssuers !== [] && ! in_array($issuer, $this->allowedIssuers, true)) {
            throw new ClaimMismatch('Service token issuer is not allow-listed.');
        }

        return $claims;
    }

    private function issuingSecret(): HmacSecret
    {
        if ($this->secrets !== []) {
            $own = $this->secrets[$this->issuer] ?? null;

            if ($own === null) {
                throw ServiceAuthMisconfigured::ownIssuerSecretMissing($this->issuer);
            }

            return $this->hmac($own);
        }

        return $this->sharedSecret();
    }

    /**
     * In per-issuer mode the verification secret is selected by the token's
     * `iss`; in shared mode it is the mesh-wide secret.
     */
    private function verificationSecret(string $jwt): HmacSecret
    {
        if ($this->secrets === []) {
            return $this->sharedSecret();
        }

        $secret = $this->secrets[$this->unverifiedIssuer($jwt)] ?? null;

        // Unknown issuer: return a fixed dummy secret so the decoder still runs
        // one full HMAC verification (which cannot match) and fails with
        // InvalidSignature — identical work and error to a known issuer with a
        // bad signature. Throwing here instead would leak, via timing and the
        // error reason, which issuer names are configured.
        if ($secret === null) {
            return $this->hmac(self::DUMMY_SECRET);
        }

        return $this->hmac($secret);
    }

    /**
     * Reads `iss` from the not-yet-verified payload purely to select the
     * per-issuer secret — the same pattern as a `kid` lookup. Every security
     * decision still happens in the {@see Decoder} with the selected secret;
     * a forged `iss` merely selects a secret its signature cannot match.
     */
    private function unverifiedIssuer(string $jwt): string
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new MalformedToken('A compact JWS must have exactly three segments.');
        }

        try {
            $payload = json_decode(Base64Url::decode($parts[1]), true, 512, JSON_THROW_ON_ERROR);
        } catch (InvalidEncodingException) {
            throw new MalformedToken('The token payload is not valid base64url.');
        } catch (JsonException) {
            throw new MalformedToken('The token payload is not valid JSON.');
        }

        $issuer = is_array($payload) ? ($payload['iss'] ?? null) : null;

        if (! is_string($issuer) || $issuer === '') {
            throw new ClaimMismatch('Service token issuer is missing.');
        }

        return $issuer;
    }

    /**
     * @throws ServiceAuthMisconfigured
     */
    private function sharedSecret(): HmacSecret
    {
        if ($this->secret === null || $this->secret === '') {
            throw ServiceAuthMisconfigured::missingSecret();
        }

        return $this->hmac($this->secret);
    }

    /**
     * A config-supplied secret that fails the {@see HmacSecret} guards (PEM,
     * too short, no entropy) is an operator error, so it surfaces as a 500 —
     * never a 401.
     */
    private function hmac(#[\SensitiveParameter] string $value): HmacSecret
    {
        try {
            return HmacSecretFactory::make($value);
        } catch (JwtException $e) {
            throw ServiceAuthMisconfigured::invalidSecret($e->getMessage());
        }
    }
}
