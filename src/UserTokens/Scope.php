<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\UserTokens;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

/**
 * The canonical wire scopes used across the package.
 *
 * A backed enum (org convention over a string-const bag) gives the four
 * built-in scopes a discoverable, type-safe home. Custom scopes remain free
 * strings — {@see UserTokenIssuer::mint()}
 * accepts a `Scope|string`, so callers may pass a case for the built-ins or any
 * string for their own scopes.
 */
enum Scope: string
{
    use Helpers;

    case Access = 'access';

    case TwoFaPending = '2fa_pending';

    case EmailVerify = 'email_verify';

    case Service = 'service';
}
