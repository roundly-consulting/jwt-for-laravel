<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Jwt\Denylist\Contracts\Denylist;
use RoundlyConsulting\Jwt\Exceptions\JwtMisconfigured;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Support\KeyRepository;
use RoundlyConsulting\Jwt\Tests\Fixtures\CustomIdentity;
use RoundlyConsulting\Jwt\Tests\Fixtures\TokenVersionResolver;
use RoundlyConsulting\Jwt\Tests\Fixtures\User;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenIssuer;
use RoundlyConsulting\Jwt\UserTokens\Contracts\UserTokenVerifier;

beforeEach(function (): void {
    CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestamp(1_700_000_000));

    config([
        'jwt.issuer' => 'jwt-issuer',
        'jwt.audience' => 'web',
        'jwt.private_key_path' => fixturesDir().'/keys/jwt-private.pem',
        'jwt.public_key_path' => fixturesDir().'/keys/jwt-public.pem',
        'jwt.leeway' => 0,
        'jwt.denylist.store' => 'array',
        'auth.guards.api' => ['driver' => 'jwt'],
    ]);

    Route::middleware('auth:api')->get('/protected', fn () => response()->json([
        'id' => auth()->id(),
    ]));
});

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function mint(string $scope = 'access', array $extra = []): string
{
    return app(UserTokenIssuer::class)->mint('user-1', $scope, 900, $extra)->token;
}

it('authenticates a valid access token in claims mode', function (): void {
    $this->withToken(mint())->getJson('/protected')
        ->assertOk()
        ->assertJson(['id' => 'user-1']);
});

it('rejects a request with no token', function (): void {
    $this->getJson('/protected')->assertUnauthorized();
});

it('rejects a token whose scope is not access', function (string $scope): void {
    $this->withToken(mint($scope))->getJson('/protected')->assertUnauthorized();
})->with(['2fa_pending', 'email_verify', 'anything']);

it('rejects a tampered token', function (): void {
    $token = mint();
    [$h, $p, $s] = explode('.', $token);

    $this->withToken($h.'.'.$p.'x.'.$s)->getJson('/protected')->assertUnauthorized();
});

it('rejects a denylisted jti', function (): void {
    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);
    app(Denylist::class)->deny($issued->jti, CarbonImmutable::now()->addSeconds(900));

    $this->withToken($issued->token)->getJson('/protected')->assertUnauthorized();
});

/*
 * The verifier accepts a token until `exp + leeway`, so a denial that lapses at `exp`
 * hands a logged-out token back its access for the length of the leeway.
 */
it('keeps a logged-out token rejected through the verification leeway', function (): void {
    config(['jwt.leeway' => 30]);

    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);
    Jwt::logout($issued);

    // Past `exp`, inside the leeway: the signature and clock still say "valid".
    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(910));
    expect(app(UserTokenVerifier::class)->verify($issued->token)->string('jti'))->toBe($issued->jti);

    $this->withToken($issued->token)->getJson('/protected')->assertUnauthorized();
});

it('denies a token logged out after its exp but inside the leeway', function (): void {
    config(['jwt.leeway' => 30]);

    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);

    CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(905));
    Jwt::denyClaims(app(UserTokenVerifier::class)->verify($issued->token));

    $this->withToken($issued->token)->getJson('/protected')->assertUnauthorized();
});

it('still authenticates a denylisted jti when the check is disabled', function (): void {
    config(['jwt.guard.check_denylist' => false]);

    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);
    app(Denylist::class)->deny($issued->jti, CarbonImmutable::now()->addSeconds(900));

    $this->withToken($issued->token)->getJson('/protected')->assertOk();
});

it('rejects a stale token version', function (): void {
    config(['jwt.guard.token_version' => fn () => 5]);

    $this->withToken(mint('access', ['tv' => 4]))->getJson('/protected')->assertUnauthorized();
});

it('accepts a fresh token version', function (): void {
    config(['jwt.guard.token_version' => fn () => 5]);

    $this->withToken(mint('access', ['tv' => 5]))->getJson('/protected')->assertOk();
});

it('rejects a missing token version when a callback is configured', function (): void {
    config(['jwt.guard.token_version' => fn () => 5]);

    $this->withToken(mint('access'))->getJson('/protected')->assertUnauthorized();
});

it('rejects a signed token whose tv claim is mistyped, as a 401 not a 500', function (): void {
    config(['jwt.guard.token_version' => fn () => 5]);

    $this->withToken(mint('access', ['tv' => 'not-an-int']))->getJson('/protected')->assertUnauthorized();
});

it('rejects a signed token with a malformed permissions claim, as a 401 not a 500', function (): void {
    $this->withToken(mint('access', ['permissions' => ['posts.view', 42]]))
        ->getJson('/protected')
        ->assertUnauthorized();
});

it('surfaces a missing public key as a 500, not a silent 401', function (): void {
    $token = mint();

    config(['jwt.public_key_path' => fixturesDir().'/keys/does-not-exist.pem']);
    app()->forgetInstance(UserTokenVerifier::class);
    app()->forgetInstance(KeyRepository::class);
    Auth::forgetGuards();

    $this->withToken($token)->getJson('/protected')->assertStatus(500);
});

it('does not validate a denylisted or wrong-scope token', function (): void {
    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);
    app(Denylist::class)->deny($issued->jti, CarbonImmutable::now()->addSeconds(900));

    $guard = Auth::guard('api');

    expect($guard->validate(['token' => $issued->token]))->toBeFalse()
        ->and($guard->validate(['token' => mint('email_verify')]))->toBeFalse()
        ->and($guard->validate(['token' => mint()]))->toBeTrue();
});

it('resolves a database user in provider mode and enforces token version', function (): void {
    config([
        'auth.guards.api' => ['driver' => 'jwt', 'provider' => 'users'],
        'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
        'jwt.guard.token_version' => fn (User $user): int => $user->token_version,
    ]);

    Schema::create('users', function ($table): void {
        $table->increments('id');
        $table->unsignedInteger('token_version')->default(1);
    });

    $user = User::query()->create(['token_version' => 3]);

    $fresh = app(UserTokenIssuer::class)->mint((string) $user->id, 'access', 900, ['tv' => 3])->token;
    $stale = app(UserTokenIssuer::class)->mint((string) $user->id, 'access', 900, ['tv' => 2])->token;

    $this->withToken($fresh)->getJson('/protected')->assertOk()->assertJson(['id' => $user->id]);
    $this->withToken($stale)->getJson('/protected')->assertUnauthorized();
});

it('verifies against the guard\'s own audience', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'audience' => 'clients']]);

    $forClients = app(UserTokenIssuer::class)->mint('user-1', 'access', 900, [], 'clients')->token;

    $this->withToken($forClients)->getJson('/protected')->assertOk();
    $this->withToken(mint())->getJson('/protected')->assertUnauthorized();
});

it('requires the guard\'s own scope', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'scope' => 'partner']]);

    $this->withToken(mint('partner'))->getJson('/protected')->assertOk();
    $this->withToken(mint())->getJson('/protected')->assertUnauthorized();
});

it('honours the guard\'s own denylist switch', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'check_denylist' => false]]);

    $issued = app(UserTokenIssuer::class)->mint('user-1', 'access', 900);
    app(Denylist::class)->deny($issued->jti, CarbonImmutable::now()->addSeconds(900));

    $this->withToken($issued->token)->getJson('/protected')->assertOk();
});

it('builds the guard\'s own identity class', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'identity' => CustomIdentity::class]]);

    Route::middleware('auth:api')->get('/identity', fn () => response()->json(['class' => auth()->user()::class]));

    $this->withToken(mint())->getJson('/identity')->assertOk()->assertJson(['class' => CustomIdentity::class]);
});

it('enforces the guard\'s own invokable token_version resolver', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'token_version' => TokenVersionResolver::class]]);

    $this->withToken(mint('access', ['tv' => 7]))->getJson('/protected')->assertOk();
    $this->withToken(mint('access', ['tv' => 6]))->getJson('/protected')->assertUnauthorized();
});

it('prefers the guard\'s token_version over the global one', function (): void {
    config([
        'jwt.guard.token_version' => fn (): int => 1,
        'auth.guards.api' => ['driver' => 'jwt', 'token_version' => TokenVersionResolver::class],
    ]);

    $this->withToken(mint('access', ['tv' => 7]))->getJson('/protected')->assertOk();
    $this->withToken(mint('access', ['tv' => 1]))->getJson('/protected')->assertUnauthorized();
});

/*
 * A token_version the guard cannot call must never silently switch the freshness
 * check off: a bumped version would then revoke nothing ("log out everywhere" that
 * logs nobody out). It is an operator error, surfaced like a missing key — a 500,
 * not a quiet pass.
 */
it('refuses a token_version it cannot resolve to a callable', function (string $scope, mixed $value): void {
    config($scope === 'guard'
        ? ['auth.guards.api' => ['driver' => 'jwt', 'token_version' => $value]]
        : ['jwt.guard.token_version' => $value]);

    Auth::guard('api');
})->with([
    'unknown class (guard)' => ['guard', 'App\\Auth\\MissingTokenVersion'],
    'unknown class (global)' => ['global', 'App\\Auth\\MissingTokenVersion'],
    'class without __invoke (guard)' => ['guard', stdClass::class],
    'class without __invoke (global)' => ['global', stdClass::class],
    'not a class-string or closure (guard)' => ['guard', ['not', 'callable']],
    'not a class-string or closure (global)' => ['global', 42],
])->throws(JwtMisconfigured::class, 'token_version');

it('survives a config:cache round-trip with an invokable per-guard token_version', function (): void {
    config(['auth.guards.api' => ['driver' => 'jwt', 'audience' => 'clients', 'token_version' => TokenVersionResolver::class]]);

    // config:cache writes the repository with var_export() and loads it back —
    // a closure cannot make that trip, a class-string can.
    $cached = eval('return '.var_export(config()->all(), true).';');
    config()->set($cached);
    Auth::forgetGuards();

    $token = app(UserTokenIssuer::class)->mint('user-1', 'access', 900, ['tv' => 7], 'clients')->token;

    $this->withToken($token)->getJson('/protected')->assertOk();
});
