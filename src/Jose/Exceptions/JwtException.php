<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

use RuntimeException;

/**
 * Base exception for every JOSE / JWT error raised by the package.
 *
 * Catch this to handle any token failure uniformly; catch a subclass for a
 * precise cause.
 */
class JwtException extends RuntimeException {}
