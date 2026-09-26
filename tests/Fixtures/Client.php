<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * A second, fully separate account type (own table) for the multi-guard tests:
 * its primary keys deliberately collide with {@see User}'s.
 *
 * @property int $id
 * @property int $token_version
 */
final class Client extends Authenticatable
{
    protected $table = 'clients';

    protected $guarded = [];

    public $timestamps = false;
}
