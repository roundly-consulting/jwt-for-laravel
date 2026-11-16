<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose\Exceptions;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;

/**
 * The token verified, but its `jti` is on the denylist: it was revoked (logged out,
 * or its run ended) before it expired. Raised only by a verify that asks for the
 * check (`checkDenylist: true`) or a guard configured to make it.
 *
 * {@see self::ERROR_CODE} is a stable, locale-independent code for an API error
 * body; the message is translated (`jwt::errors.token_revoked`, en + sk).
 */
final class TokenRevoked extends JwtException
{
    public const string ERROR_CODE = 'token_revoked';

    private const string KEY = 'jwt::errors.token_revoked';

    private string $jti = '';

    public static function forJti(string $jti): self
    {
        $exception = new self(self::translatedMessage());
        $exception->jti = $jti;

        return $exception;
    }

    /**
     * The revoked token's id — safe to log; it authorizes nothing on its own.
     */
    public function jti(): string
    {
        return $this->jti;
    }

    private static function translatedMessage(): string
    {
        $container = Container::getInstance();

        if ($container->bound('translator')) {
            $line = $container->make(Translator::class)->get(self::KEY);

            if (is_string($line) && $line !== self::KEY) {
                return $line;
            }
        }

        return 'The token has been revoked.';
    }
}
