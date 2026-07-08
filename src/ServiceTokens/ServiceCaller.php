<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RoundlyConsulting\Jwt\ServiceTokens\Contracts\ServiceTokenIssuer;

/**
 * Outbound helper: attaches a freshly issued HS256 service token as a bearer
 * credential to an internal HTTP request.
 */
final class ServiceCaller
{
    public function __construct(private readonly ServiceTokenIssuer $issuer) {}

    /**
     * A new pending request already carrying a fresh service token for the
     * given audience.
     */
    public function request(?string $audience = null): PendingRequest
    {
        return Http::withToken($this->issuer->issue($audience)->token);
    }

    /**
     * Attach a fresh service token to an existing pending request.
     */
    public function authenticate(PendingRequest $request, ?string $audience = null): PendingRequest
    {
        return $request->withToken($this->issuer->issue($audience)->token);
    }
}
