<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Carbon\CarbonImmutable;
use DateInterval;
use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Str;
use JsonException;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\Hex;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Random\Bytes;
use RoundlyConsulting\Crypto\Signature\Algorithm;
use RoundlyConsulting\Crypto\Signature\Key\HmacSecret;
use RoundlyConsulting\Jwt\Events\ServiceTokenIssued;
use RoundlyConsulting\Jwt\Jose\Claims;
use RoundlyConsulting\Jwt\Jose\Decoder;
use RoundlyConsulting\Jwt\Jose\Encoder;
use RoundlyConsulting\Jwt\Jose\Exceptions\ClaimMismatch;
use RoundlyConsulting\Jwt\Jose\Exceptions\InvalidSignature;
use RoundlyConsulting\Jwt\Jose\Exceptions\JwtException;
use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuerWithOptions;
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
final class NativeServiceTokenService implements ServiceTokenIssuerWithOptions, ServiceTokenVerifier
{
    private const SCOPE = Scope::Service->value;

    /**
     * The longest `sub` a service token may carry, in bytes. A subject is an
     * identifier (`agent-run:01J…`), not a payload; the bound keeps a caller from
     * inflating every token toward the verifier's size limit.
     */
    public const int MAX_SUBJECT_BYTES = 255;

    /**
     * The claims a caller may never supply: every one of them is a statement this
     * class makes about the token, or one the PLATFORM makes about an identity —
     * not a fact the caller is entitled to assert.
     *
     * `sub` is here although a service token may carry one: only through the
     * explicit, validated `$subject` option of {@see issue()}, never as a raw claim,
     * so no caller sets it by accident (e.g. by forwarding a request body). A service
     * token's `sub` names a subject for the RECEIVING service to read; it never
     * authenticates as a user — the `jwt` guard pins RS256 and `scope=access`, so an
     * HS256 `scope=service` token is refused there before `sub` is read. The four after it are what
     * `TokenUser::fromClaims` reads — a token asserting its own `permissions` that
     * some consumer later hydrates into a `TokenUser` is precisely the failure this
     * guard exists to prevent.
     *
     * @var list<string>
     */
    private const REGISTERED = [
        'iss', 'aud', 'iat', 'nbf', 'exp', 'jti', 'scope', 'sub',
        'permissions', 'tv', 'email', 'email_verified',
    ];

    /**
     * A random key, drawn per instance, used only to burn an HMAC verification for
     * an unknown issuer, so a known and an unknown `iss` do identical work and fail
     * identically ({@see InvalidSignature}): the issuer set can't be enumerated by
     * timing or error reason. It never leaves this object, and an unknown issuer is
     * refused after decode() even if its signature somehow verified against it.
     */
    private readonly string $unknownIssuerSecret;

    /**
     * @param  array<string, string>  $secrets  per-issuer secrets; empty ⇒ shared `secret` mode
     * @param  list<string>  $allowedIssuers  empty ⇒ any issuer accepted
     * @param  int  $maxTtl  the longest per-call `$ttl` {@see issue()} accepts (`jwt.service.max_ttl`);
     *                       the configured default `$ttl` is the operator's own and not bound by it
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
        private readonly int $maxTtl = 3600,
    ) {
        $this->unknownIssuerSecret = Hex::encode(Bytes::generate(32));
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function issue(
        ?string $audience = null,
        array $claims = [],
        int|DateInterval|null $ttl = null,
        ?string $subject = null,
    ): IssuedToken {
        if ($this->issuer === '') {
            throw ServiceAuthMisconfigured::missingIssuer();
        }

        $audience ??= $this->defaultAudience;

        // An audience-less token can never verify anywhere (the receiver pins
        // `aud` to its own name), so refuse to mint one.
        if ($audience === null || $audience === '') {
            throw ServiceAuthMisconfigured::missingAudience();
        }

        // Per-call options are validated before the secret is touched, so a bad
        // call fails the same way whatever the keying mode.
        $seconds = $ttl === null ? $this->ttl : $this->ttlSeconds($ttl);

        if ($subject !== null) {
            $this->assertValidSubject($subject);
        }

        $secret = $this->issuingSecret();

        $now = CarbonImmutable::now();
        $expiresAt = $now->addSeconds($seconds);
        $jti = (string) Str::uuid();

        // Registered claims are written LAST, so an extra claim can never move the
        // audience, the expiry or the scope. Rejecting outright rather than letting
        // the merge order quietly win: a caller passing `aud` believes it did
        // something, and silently ignoring it is how that belief survives to
        // production.
        $reserved = array_intersect(array_keys($claims), self::REGISTERED);
        if ($reserved !== []) {
            throw ServiceAuthMisconfigured::reservedClaims(array_values($reserved));
        }

        // `sub` only through the explicit `$subject` option, after the reserved-claim
        // check above has refused it as a raw claim.
        $claims = [
            ...$claims,
            ...($subject === null ? [] : ['sub' => $subject]),
            'iss' => $this->issuer,
            'aud' => $audience,
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $expiresAt->getTimestamp(),
            'jti' => $jti,
            'scope' => self::SCOPE,
        ];

        $token = $this->encoder->encode($claims, $secret, Algorithm::HS256);

        $this->events?->dispatch(new ServiceTokenIssued($this->issuer, $audience, $jti, $expiresAt, $subject));

        return new IssuedToken($token, $expiresAt, $jti);
    }

    public function verify(#[\SensitiveParameter] string $jwt): Claims
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

        $issuerSecret = $this->issuerSecret($jwt);

        $claims = $this->decoder->decode($jwt, $issuerSecret ?? $this->hmac($this->unknownIssuerSecret), Algorithm::HS256, $this->leeway);

        // An issuer absent from the per-issuer map is never accepted, whatever
        // the signature did: the burn above only equalises the work.
        if ($issuerSecret === null) {
            throw new InvalidSignature(Algorithm::HS256->value.' signature verification failed.');
        }

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

    /**
     * A per-call lifetime in whole seconds, within 1..`maxTtl`. An interval is
     * measured from a fixed instant, so the same interval always means the same
     * number of seconds; fractional seconds are refused rather than rounded.
     *
     * @throws ServiceAuthMisconfigured
     */
    private function ttlSeconds(int|DateInterval $ttl): int
    {
        if ($ttl instanceof DateInterval) {
            if ($ttl->f !== 0.0) {
                throw ServiceAuthMisconfigured::invalidTtl($this->maxTtl);
            }

            $ttl = (new DateTimeImmutable('@0'))->add($ttl)->getTimestamp();
        }

        if ($ttl < 1 || $ttl > $this->maxTtl) {
            throw ServiceAuthMisconfigured::invalidTtl($this->maxTtl);
        }

        return $ttl;
    }

    /**
     * A subject is a non-empty identifier of at most {@see MAX_SUBJECT_BYTES} bytes
     * of valid UTF-8, with no control characters and no surrounding whitespace —
     * `" run-1"` and `"run-1"` must never be two different subjects. The value is
     * never echoed in the error.
     *
     * @throws ServiceAuthMisconfigured
     */
    private function assertValidSubject(string $subject): void
    {
        $reason = match (true) {
            trim($subject) === '' => 'it is empty',
            strlen($subject) > self::MAX_SUBJECT_BYTES => 'it is longer than '.self::MAX_SUBJECT_BYTES.' bytes',
            preg_match('//u', $subject) !== 1 => 'it is not valid UTF-8',
            preg_match('/\p{Cc}/u', $subject) === 1 => 'it contains a control character',
            trim($subject) !== $subject => 'it has leading or trailing whitespace',
            default => null,
        };

        if ($reason !== null) {
            throw ServiceAuthMisconfigured::invalidSubject($reason);
        }
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
     * `iss`; in shared mode it is the mesh-wide secret. Null means an issuer
     * absent from the per-issuer map: the caller still burns one full HMAC
     * verification with the per-instance random key and then fails with
     * InvalidSignature — identical work and error to a known issuer with a bad
     * signature. Throwing here instead would leak, via timing and the error
     * reason, which issuer names are configured.
     */
    private function issuerSecret(#[\SensitiveParameter] string $jwt): ?HmacSecret
    {
        if ($this->secrets === []) {
            return $this->sharedSecret();
        }

        $secret = $this->secrets[$this->unverifiedIssuer($jwt)] ?? null;

        return $secret === null ? null : $this->hmac($secret);
    }

    /**
     * Reads `iss` from the not-yet-verified payload purely to select the
     * per-issuer secret — the same pattern as a `kid` lookup. Every security
     * decision still happens in the {@see Decoder} with the selected secret;
     * a forged `iss` merely selects a secret its signature cannot match.
     */
    private function unverifiedIssuer(#[\SensitiveParameter] string $jwt): string
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
