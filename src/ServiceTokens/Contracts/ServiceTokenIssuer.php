<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\ServiceTokens\Contracts;

use RoundlyConsulting\Jwt\UserTokens\IssuedToken;

interface ServiceTokenIssuer
{
    /**
     * Issue an HS256 service token for the given audience (defaults to the
     * configured service audience).
     *
     * `$claims` adds caller-defined claims to the token. It exists for the case a
     * request body cannot serve: a token handed to a subprocess (an MCP server, a
     * worker) which then acts on its holder's behalf, where anything the SUBJECT
     * could write is by definition not an authorization. A registered claim name
     * (`iss`, `aud`, `exp`, `scope`, …) is rejected rather than merged — a caller
     * that could overwrite `aud` could address any service in the mesh.
     *
     * @param  array<string, mixed>  $claims  additional, non-registered claims
     */
    public function issue(?string $audience = null, array $claims = []): IssuedToken;
}
