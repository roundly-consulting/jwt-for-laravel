<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

/**
 * Thrown when a claim set cannot be serialised to JSON — e.g. a host-supplied
 * extra claim containing non-UTF-8 bytes. Keeps minting failures inside the
 * package exception hierarchy so consumers catching {@see JwtException} handle
 * them uniformly.
 */
final class UnencodableClaims extends JwtException {}
