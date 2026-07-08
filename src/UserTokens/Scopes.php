<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

/**
 * The canonical wire scope strings used across the package.
 *
 * These are deliberately plain string constants — NOT an enum — so custom
 * scopes remain free strings via {@see UserTokenIssuer::mint()} while the four
 * built-in scopes get a discoverable, greppable, autocompleteable home.
 */
final class Scopes
{
    public const string ACCESS = 'access';

    public const string TWO_FA_PENDING = '2fa_pending';

    public const string EMAIL_VERIFY = 'email_verify';

    public const string SERVICE = 'service';
}
