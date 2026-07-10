<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

/**
 * Thrown when a token's `typ` header is present but is not `JWT` — RFC 8725
 * §3.11 explicit typing, which prevents cross-JWT confusion between artifacts
 * signed with the same key but a different media type.
 */
final class UnexpectedTokenType extends JwtException {}
