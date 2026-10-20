<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * A user keyed by a string handle, for the subject-binding tests: MySQL's default
 * collation compares it case- and accent-insensitively.
 *
 * @property string $handle
 */
final class HandleUser extends Authenticatable
{
    protected $table = 'handle_users';

    protected $primaryKey = 'handle';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    public $timestamps = false;
}
