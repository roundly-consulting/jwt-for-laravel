<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Jwt\Tests\Fixtures\HandleUser;
use RoundlyConsulting\Jwt\Tests\Fixtures\LooseUserProvider;
use RoundlyConsulting\Jwt\Tests\Fixtures\User;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;

/*
 * Provider mode hands the token's `sub` to the user provider, and the database compares
 * it by its own coercion rules. MySQL and SQLite read "01", "+1", "1.0" or "1e0" as the
 * integer 1 (MySQL also "1abc" and a UUID that starts with a digit). PostgreSQL reads
 * " 1" and "0x1" as 1 and throws 22P02 on "1abc". A token signed with such a subject
 * logged in as user 1, or crashed with a 500. The guard now accepts a user only when its
 * identifier IS the subject, and never sends a non-integer subject to an int-keyed model.
 *
 * These run on every engine of the CI matrix (SQLite, MySQL 8, PostgreSQL 16).
 */
beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'users'],
        'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
    ]);

    Schema::create('users', function ($table): void {
        $table->increments('id');
    });

    User::query()->create();
    User::query()->create();

    Route::middleware('auth:api')->get('/me', fn () => response()->json(['id' => auth()->id()]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function tokenForSubject(string $subject): string
{
    return app(UserTokenIssuer::class)->mint($subject, 'access', 900)->token;
}

/**
 * Subjects a signed token could carry that are not the canonical key of any user.
 *
 * @return array<string, array{0: string}>
 */
function nonCanonicalSubjects(): array
{
    return [
        '"1abc"' => ['1abc'],
        '"01"' => ['01'],
        '" 1"' => [' 1'],
        '"1 "' => ['1 '],
        '"1\n"' => ["1\n"],
        '"+1"' => ['+1'],
        '"1.0"' => ['1.0'],
        '"1e0"' => ['1e0'],
        '"0.1e1"' => ['0.1e1'],
        '"0x1"' => ['0x1'],
        '"2-1"' => ['2-1'],
        'uuid' => ['1f0e8a2c-9b7d-4c1e-8f3a-2d6b5e4c3a21'],
        '"abc"' => ['abc'],
        'empty' => [''],
        'past PHP_INT_MAX' => ['9223372036854775808'],
    ];
}

it('logs a canonical subject in as exactly that user', function (string $subject, int $id): void {
    $this->withToken(tokenForSubject($subject))->getJson('/me')->assertOk()->assertExactJson(['id' => $id]);
})->with([
    'user 1' => ['1', 1],
    'user 2' => ['2', 2],
]);

it('refuses a subject the database would coerce to another user, with a 401', function (string $subject): void {
    $this->withToken(tokenForSubject($subject))->getJson('/me')->assertUnauthorized();
})->with(nonCanonicalSubjects());

it('never sends a non-integer subject to an int-keyed model', function (string $subject): void {
    $queries = 0;

    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        $queries += str_contains($query->sql, 'users') ? 1 : 0;
    });

    $this->withToken(tokenForSubject($subject))->getJson('/me')->assertUnauthorized();

    expect($queries)->toBe(0);
})->with(nonCanonicalSubjects());

it('refuses a canonical subject that matches no user', function (): void {
    $this->withToken(tokenForSubject('3'))->getJson('/me')->assertUnauthorized();
    $this->withToken(tokenForSubject('-1'))->getJson('/me')->assertUnauthorized();
});

/*
 * A string key compares by the column's collation: MySQL's default is case- and
 * accent-insensitive, so "ALICE" finds alice there.
 */
it('refuses a string subject that only matches by collation', function (string $subject): void {
    config([
        'auth.providers.handles' => ['driver' => 'eloquent', 'model' => HandleUser::class],
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'handles'],
    ]);

    Schema::create('handle_users', function ($table): void {
        $table->string('handle')->primary();
    });

    HandleUser::query()->create(['handle' => 'alice']);

    $this->withToken(tokenForSubject('alice'))->getJson('/me')->assertOk()->assertExactJson(['id' => 'alice']);
    $this->withToken(tokenForSubject($subject))->getJson('/me')->assertUnauthorized();
})->with([
    '"ALICE"' => ['ALICE'],
    '"Alice"' => ['Alice'],
    '"alicé"' => ['alicé'],
]);

/*
 * The identity check holds for any user provider, not only Eloquent: a provider that
 * finds user 7 for "007" does not log "007" in as user 7.
 */
it('refuses a user whose identifier is not the subject, from any provider', function (): void {
    Auth::provider('loose', fn (): LooseUserProvider => new LooseUserProvider);
    config([
        'auth.providers.loose' => ['driver' => 'loose'],
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'loose'],
    ]);

    $this->withToken(tokenForSubject('7'))->getJson('/me')->assertOk()->assertExactJson(['id' => 7]);
    $this->withToken(tokenForSubject('007'))->getJson('/me')->assertUnauthorized();
    $this->withToken(tokenForSubject('7.0'))->getJson('/me')->assertUnauthorized();
});

it('compares a stringable identifier by its string form', function (): void {
    $identifier = new class implements Stringable
    {
        public function __toString(): string
        {
            return '7';
        }
    };

    Auth::provider('loose', fn (): LooseUserProvider => new LooseUserProvider($identifier));
    config([
        'auth.providers.loose' => ['driver' => 'loose'],
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'loose'],
    ]);

    $this->withToken(tokenForSubject('7'))->getJson('/me')->assertOk();
    $this->withToken(tokenForSubject('07'))->getJson('/me')->assertUnauthorized();
});

it('refuses a user whose identifier is not a scalar', function (): void {
    Auth::provider('loose', fn (): LooseUserProvider => new LooseUserProvider(['7']));
    config([
        'auth.providers.loose' => ['driver' => 'loose'],
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'loose'],
    ]);

    $this->withToken(tokenForSubject('7'))->getJson('/me')->assertUnauthorized();
});
